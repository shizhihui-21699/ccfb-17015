package knxsec

import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom

/**
 * 隧道网关的会话服务器（KNX IP Secure 会话层）。
 *
 * 会话耗尽攻击的防御设计（核心难点）：
 * - 收到 SESSION_REQUEST 时【不分配任何会话状态】，只回一个无状态 cookie
 *   （类似 DTLS 的 HelloVerifyRequest / IKEv2 的 COOKIE 通知）：
 *   cookie = AES-CCM(cookieKey, 服务器临时私钥‖服务器公钥‖时间槽)，
 *   AAD 绑定 源地址‖客户端公钥。攻击者用伪造源 IP 泛洪，收不到响应也就
 *   拿不出合法 cookie，网关上什么都不会留下。
 * - SESSION_AUTHENTICATE 必须回显 cookie 且通过口令 HMAC 校验后才分配会话表项；
 *   已用过的 cookie 在时间槽内缓存，防止录制重放批量换会话。
 * - 每源 IP + 全局两级令牌桶限流：全局桶容量按"整楼面板同时上电"配置，
 *   单 IP 桶很小，攻击者单点打不满全局，合法设备重试即可挤进来。
 * - 会话表硬上限，满时回 BUSY；已建立的会话【永不】因新连接压力被驱逐。
 *
 * 心跳与夜间节能：
 * - 会话超时 = 设备申报心跳 × 2.5，钳制在 [30s, 900s]；
 *   夜间模式心跳拉长到 60s 时超时自动放宽到 150s，不会误杀。
 * - 单播 48 位序号与时间无关，心跳间隔再长也不会"过期"。
 */
class SessionServer(
    password: String,
    val maxSessions: Int = 64,
    val now: () -> Long,
    private val send: (to: Endpoint, data: ByteArray) -> Unit,
    globalCapacity: Double = 128.0,
    globalRefillPerSec: Double = 64.0,
    perIpCapacity: Double = 4.0,
    perIpRefillPerSec: Double = 1.0,
) {
    private val pwKey = Crypto.passwordKey(password)
    private val cookieKey = ByteArray(16).also(SecureRandom()::nextBytes)
    private val globalBucket = TokenBucket(globalCapacity, globalRefillPerSec, now)
    private val perIp = PerKeyRateLimiter(perIpCapacity, perIpRefillPerSec, now)

    private val sessions = LinkedHashMap<Int, Session>()
    private var nextId = 1

    /** 已消费的 cookie（按时间槽清理，防录制重放换会话）。 */
    private val usedCookies = HashSet<String>()
    private var usedCookieSlot = -1L

    var onData: ((sessionId: Int, from: Endpoint, inner: Frame) -> Unit)? = null

    val stats = Stats()

    class Stats {
        var requests = 0
        var rateLimited = 0
        var authAttempts = 0
        var authFailures = 0
        var cookieRejected = 0
        var busyRejections = 0
        var established = 0
        var replaysDropped = 0
        var wrapperAuthFailures = 0
        var expired = 0
        var wrongPeerDropped = 0
    }

    class Session(
        val id: Int,
        val peer: Endpoint,
        val crypto: SessionCrypto,
        heartbeatMs: Long,
        val now: () -> Long,
    ) {
        var recvSeq = -1L
        var sendSeq = 0L
        var lastActivity = now()
        val timeoutMs = (heartbeatMs + heartbeatMs * 3 / 2).coerceIn(30_000L, 900_000L)
        fun expired(): Boolean = now() - lastActivity > timeoutMs
    }

    val sessionCount: Int get() = sessions.size
    fun session(id: Int): Session? = sessions[id]

    fun handle(from: Endpoint, frame: Frame) {
        when (frame.serviceType) {
            ServiceType.SESSION_REQUEST -> onSessionRequest(from, frame)
            ServiceType.SESSION_AUTHENTICATE -> onAuthenticate(from, frame)
            ServiceType.SECURE_WRAPPER -> onSecureWrapper(from, frame)
        }
    }

    // ---------- 阶段 1：会话请求（X25519 密钥交换，无状态） ----------

    private fun onSessionRequest(from: Endpoint, frame: Frame) {
        stats.requests++
        val clientPub = Msg.parseSessionRequest(frame) ?: return
        if (!globalBucket.tryConsume() || !perIp.tryConsume(from.host)) {
            stats.rateLimited++
            return // 静默丢弃，不消耗任何后续资源
        }
        val kp = Crypto.generateKeyPair()
        val cookie = buildCookie(kp.private, kp.public, currentSlot(), from, clientPub)
        send(from, Msg.sessionResponse(0, Crypto.publicKeyBytes(kp.public), cookie).encode())
        // 注意：此处不保存 kp、不建表项 —— 服务器是无状态的
    }

    // ---------- 阶段 2：会话认证（口令派生校验，通过才分配状态） ----------

    private fun onAuthenticate(from: Endpoint, frame: Frame) {
        stats.authAttempts++
        val msg = Msg.parseAuthenticate(frame) ?: return

        val slot = currentSlot()
        // 清理过期时间槽的已用 cookie 缓存
        if (usedCookieSlot != slot) {
            usedCookies.clear()
            usedCookieSlot = slot
        }
        val cookieId = java.util.Base64.getEncoder().encodeToString(msg.cookie)
        if (!usedCookies.add(cookieId)) {
            stats.cookieRejected++
            return // 录制重放
        }
        val recovered = parseCookie(msg.cookie, from, msg.clientPub)
        if (recovered == null) {
            stats.cookieRejected++
            return
        }
        val (serverPriv, serverPub) = recovered

        val shared = Crypto.ecdh(serverPriv, Crypto.publicKeyFromBytes(msg.clientPub))
        val expected = Crypto.hmacSha256(pwKey, msg.clientPub, Crypto.publicKeyBytes(serverPub))
            .copyOf(Crypto.TAG_LEN)
        if (!Crypto.constantTimeEquals(expected, msg.hmac)) {
            stats.authFailures++
            send(from, Msg.sessionStatus(1, 0).encode())
            return
        }
        if (sessions.size >= maxSessions) {
            stats.busyRejections++
            send(from, Msg.sessionStatus(2, 0).encode())
            return
        }
        val id = allocateId()
        sessions[id] = Session(id, from, SessionCrypto.derive(shared, id), msg.heartbeatMs, now)
        stats.established++
        send(from, Msg.sessionStatus(0, id).encode())
    }

    // ---------- 阶段 3：安全封装数据帧（48 位序号 + CCM 标签） ----------

    private fun onSecureWrapper(from: Endpoint, frame: Frame) {
        if (frame.body.size < 2) return
        val session = sessions[frame.body.rd16(0)] ?: return
        if (session.peer != from) {
            stats.wrongPeerDropped++
            return // 会话与源地址绑定，防劫持
        }
        val (seq, inner) = session.crypto.unwrap(frame) ?: run {
            stats.wrapperAuthFailures++
            return
        }
        if (seq <= session.recvSeq) {
            stats.replaysDropped++
            return // 重放/乱序旧帧
        }
        session.recvSeq = seq
        session.lastActivity = now()
        if (inner.serviceType != ServiceType.KEEPALIVE) {
            onData?.invoke(session.id, from, inner)
        }
    }

    fun sendData(sessionId: Int, inner: Frame): Boolean {
        val s = sessions[sessionId] ?: return false
        send(s.peer, s.crypto.wrap(s.sendSeq++, inner).encode())
        return true
    }

    /** 周期性调用：清理空闲超时的会话。 */
    fun sweep() {
        val it = sessions.values.iterator()
        while (it.hasNext()) {
            if (it.next().expired()) {
                it.remove()
                stats.expired++
            }
        }
    }

    // ---------- 无状态 cookie ----------

    private fun currentSlot() = now() / COOKIE_SLOT_MS

    private fun cookieNonce(slot: Long, from: Endpoint, clientPub: ByteArray): ByteArray =
        Crypto.hmacSha256(
            cookieKey,
            "cookie-nonce".toByteArray(),
            be64(slot),
            endpointBytes(from),
            clientPub
        ).copyOf(Crypto.NONCE_LEN)

    private fun buildCookie(priv: PrivateKey, pub: PublicKey, slot: Long, from: Endpoint, clientPub: ByteArray): ByteArray {
        val plain = Crypto.privateKeyBytes(priv) + Crypto.publicKeyBytes(pub) + be64(slot)
        return Crypto.ccmEncrypt(cookieKey, cookieNonce(slot, from, clientPub), endpointBytes(from) + clientPub, plain)
    }

    /** 接受当前和上一个时间槽的 cookie（容忍跨槽边界）。 */
    private fun parseCookie(cookie: ByteArray, from: Endpoint, clientPub: ByteArray): Pair<PrivateKey, PublicKey>? {
        val slot = currentSlot()
        for (candidate in listOf(slot, slot - 1)) {
            val plain = Crypto.ccmDecrypt(
                cookieKey,
                cookieNonce(candidate, from, clientPub),
                endpointBytes(from) + clientPub,
                cookie
            ) ?: continue
            if (plain.size != 72) continue
            if (plain.rd64(64) != candidate) continue
            return Crypto.privateKeyFromBytes(plain.copyOfRange(0, 32)) to
                Crypto.publicKeyFromBytes(plain.copyOfRange(32, 64))
        }
        return null
    }

    private fun allocateId(): Int {
        while (sessions.containsKey(nextId) || nextId == 0) {
            nextId = nextId % 0xFFFF + 1
        }
        return nextId++
    }

    companion object {
        const val COOKIE_SLOT_MS = 30_000L
        fun endpointBytes(ep: Endpoint): ByteArray =
            ep.host.toByteArray(Charsets.UTF_8) + be16(ep.port)
    }
}
