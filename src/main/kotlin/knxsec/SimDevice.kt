package knxsec

import java.security.KeyPair

/**
 * 模拟 KNX 面板设备：会话客户端 + 组播发送方。
 * 心跳由外部 tick() 驱动（测试用虚拟时钟，演示可接定时器）。
 */
class SimDevice(
    val deviceId: Int,
    val endpoint: Endpoint,
    val bus: LoopbackBus,
    val gateway: Endpoint,
    password: String,
    private val backboneKey: ByteArray,
    val heartbeatMs: Long = 20_000,
    val now: () -> Long,
) {
    private val pwKey = Crypto.passwordKey(password)
    val timing = TimingSynchronizer(backboneKey, now)

    var established = false
        private set
    var sessionId = 0
        private set
    var lastStatus = -1
        private set

    private var crypto: SessionCrypto? = null
    private var sendSeq = 0L
    private var recvSeq = -1L

    private var kp: KeyPair? = null
    private var pendingShared: ByteArray? = null
    private var serverPub: ByteArray? = null
    private var cookie: ByteArray? = null
    private var lastHeartbeatAt = 0L

    val receivedData = mutableListOf<Frame>()

    fun handle(from: Endpoint, data: ByteArray) {
        val frame = Frame.decode(data) ?: return
        when (frame.serviceType) {
            ServiceType.SESSION_RESPONSE -> {
                val r = Msg.parseSessionResponse(frame) ?: return
                if (r.status != 0) return
                serverPub = r.serverPub
                cookie = r.cookie
            }
            ServiceType.SESSION_STATUS -> {
                val (status, id) = Msg.parseSessionStatus(frame) ?: return
                lastStatus = status
                if (status == 0) {
                    val shared = pendingShared ?: return
                    sessionId = id
                    crypto = SessionCrypto.derive(shared, id)
                    established = true
                    lastHeartbeatAt = now()
                }
            }
            ServiceType.SECURE_WRAPPER -> {
                val c = crypto ?: return
                val (seq, inner) = c.unwrap(frame) ?: return
                if (seq <= recvSeq) return
                recvSeq = seq
                receivedData += inner
            }
            ServiceType.TIMER_NOTIFY -> {
                val (senderId, timer, tag) = TimingMaster.parseNotify(frame) ?: return
                timing.onNotify(senderId, timer, tag)
            }
        }
    }

    /** 发起会话（同步总线下一次调用完成全部握手）。 */
    fun connect(): Boolean {
        established = false
        lastStatus = -1
        val keyPair = Crypto.generateKeyPair()
        kp = keyPair
        serverPub = null
        cookie = null
        val clientPub = Crypto.publicKeyBytes(keyPair.public)
        bus.send(endpoint, gateway, Msg.sessionRequest(clientPub).encode())
        val sp = serverPub ?: return false
        val ck = cookie ?: return false
        val shared = Crypto.ecdh(keyPair.private, Crypto.publicKeyFromBytes(sp))
        pendingShared = shared
        val hmac = Crypto.hmacSha256(pwKey, clientPub, sp).copyOf(Crypto.TAG_LEN)
        bus.send(endpoint, gateway, Msg.sessionAuthenticate(clientPub, ck, hmac, heartbeatMs).encode())
        return established
    }

    /** 心跳驱动：到点就发 KEEPALIVE。 */
    fun tick() {
        if (established && now() - lastHeartbeatAt >= heartbeatMs) {
            sendSession(Frame(ServiceType.KEEPALIVE, ByteArray(0)))
            lastHeartbeatAt = now()
        }
    }

    fun sendData(payload: ByteArray) = sendSession(Frame(ServiceType.TUNNELLING_REQUEST, payload))

    private fun sendSession(inner: Frame) {
        val c = crypto ?: return
        bus.send(endpoint, gateway, c.wrap(sendSeq++, inner).encode())
    }

    /** 组播发送（路由模式）：序号取当前同步时间计数，未同步则拒绝发送。 */
    fun sendMulticast(payload: ByteArray): Boolean {
        val est = timing.estimate()
        if (est < 0) return false
        bus.send(
            endpoint,
            LoopbackBus.MULTICAST,
            McastWrapper.wrap(backboneKey, deviceId, est, Frame(ServiceType.ROUTING_INDICATION, payload)).encode()
        )
        return true
    }
}

/** 受信时间主节点：周期性广播 TIMER_NOTIFY。 */
class TimingMasterNode(
    val senderId: Int,
    private val backboneKey: ByteArray,
    private val bus: LoopbackBus,
    private val source: Endpoint,
    private val now: () -> Long,
) {
    fun broadcast() {
        bus.send(source, LoopbackBus.MULTICAST, TimingMaster.buildNotify(backboneKey, senderId, now()).encode())
    }
}
