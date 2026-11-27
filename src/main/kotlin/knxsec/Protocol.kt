package knxsec

import java.nio.ByteBuffer

/** KNXnet/IP 服务类型（安全扩展部分按 KNX IP Secure 规范编号）。 */
object ServiceType {
    const val SECURE_WRAPPER = 0x0950        // 单播安全封装
    const val SESSION_REQUEST = 0x0951
    const val SESSION_RESPONSE = 0x0952
    const val SESSION_AUTHENTICATE = 0x0953
    const val SESSION_STATUS = 0x0954
    const val TIMER_NOTIFY = 0x0944          // 组播时间通知（主干密钥保护）
    const val MCAST_WRAPPER = 0x0960         // 组播安全封装（路由模式）
    const val TUNNELLING_REQUEST = 0x0420
    const val ROUTING_INDICATION = 0x0530
    const val KEEPALIVE = 0x0209             // 会话心跳（内层帧）
}

/** KNXnet/IP 帧：06 10 | serviceType(2) | totalLength(2) | body */
class Frame(val serviceType: Int, val body: ByteArray) {
    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(HEADER_LEN + body.size)
        buf.put(0x06).put(0x10)
        buf.putShort(serviceType.toShort())
        buf.putShort((HEADER_LEN + body.size).toShort())
        buf.put(body)
        return buf.array()
    }

    companion object {
        const val HEADER_LEN = 6
        fun decode(data: ByteArray): Frame? {
            if (data.size < HEADER_LEN) return null
            val buf = ByteBuffer.wrap(data)
            if (buf.get().toInt() != 0x06 || buf.get().toInt() != 0x10) return null
            val st = buf.short.toInt() and 0xFFFF
            val len = buf.short.toInt() and 0xFFFF
            if (len != data.size) return null
            val body = ByteArray(len - HEADER_LEN)
            buf.get(body)
            return Frame(st, body)
        }
    }
}

/** 会话与封装报文的编解码。 */
object Msg {

    // ---- SESSION_REQUEST: reserved(2)=0 || clientPub(32) ----
    fun sessionRequest(clientPub: ByteArray) =
        Frame(ServiceType.SESSION_REQUEST, byteArrayOf(0, 0) + clientPub)

    fun parseSessionRequest(f: Frame): ByteArray? =
        if (f.body.size == 34) f.body.copyOfRange(2, 34) else null

    // ---- SESSION_RESPONSE: status(1) || serverPub(32) || cookie(n) ----
    fun sessionResponse(status: Int, serverPub: ByteArray, cookie: ByteArray) =
        Frame(ServiceType.SESSION_RESPONSE, byteArrayOf(status.toByte()) + serverPub + cookie)

    class Response(val status: Int, val serverPub: ByteArray, val cookie: ByteArray)

    fun parseSessionResponse(f: Frame): Response? {
        if (f.body.size < 33) return null
        return Response(
            f.body[0].toInt() and 0xFF,
            f.body.copyOfRange(1, 33),
            f.body.copyOfRange(33, f.body.size)
        )
    }

    // ---- SESSION_AUTHENTICATE: clientPub(32) || cookieLen(2) || cookie || hmac(16) || heartbeatMs(4) ----
    fun sessionAuthenticate(clientPub: ByteArray, cookie: ByteArray, hmac: ByteArray, heartbeatMs: Long): Frame {
        require(hmac.size == Crypto.TAG_LEN)
        val b = ByteBuffer.allocate(32 + 2 + cookie.size + 16 + 4)
        b.put(clientPub)
        b.putShort(cookie.size.toShort())
        b.put(cookie)
        b.put(hmac)
        b.putInt(heartbeatMs.toInt())
        return Frame(ServiceType.SESSION_AUTHENTICATE, b.array())
    }

    class Authenticate(val clientPub: ByteArray, val cookie: ByteArray, val hmac: ByteArray, val heartbeatMs: Long)

    fun parseAuthenticate(f: Frame): Authenticate? {
        val b = f.body
        if (b.size < 32 + 2 + 16 + 4) return null
        val cl = b.rd16(32)
        if (b.size != 34 + cl + 16 + 4) return null
        return Authenticate(
            b.copyOfRange(0, 32),
            b.copyOfRange(34, 34 + cl),
            b.copyOfRange(34 + cl, 34 + cl + 16),
            Integer.toUnsignedLong(ByteBuffer.wrap(b, 34 + cl + 16, 4).int)
        )
    }

    // ---- SESSION_STATUS: status(1) || sessionId(2) ----
    fun sessionStatus(status: Int, sessionId: Int) =
        Frame(ServiceType.SESSION_STATUS, byteArrayOf(status.toByte()) + be16(sessionId))

    fun parseSessionStatus(f: Frame): Pair<Int, Int>? =
        if (f.body.size == 3) (f.body[0].toInt() and 0xFF) to f.body.rd16(1) else null
}

/**
 * 单播安全封装：sessionId(2) || seq48(6) || CCM(内层帧)
 * nonce = salt(5) || sessionId(2) || seq48(6)，每会话每序号唯一。
 */
class SessionCrypto(val encKey: ByteArray, val salt: ByteArray, val sessionId: Int) {
    private fun nonce(seq: Long) = salt + be16(sessionId) + be48(seq)
    private fun aad(seq: Long) = be16(sessionId) + be48(seq)

    fun wrap(seq: Long, inner: Frame): Frame =
        Frame(ServiceType.SECURE_WRAPPER, aad(seq) + Crypto.ccmEncrypt(encKey, nonce(seq), aad(seq), inner.encode()))

    /** 返回 (序号, 内层帧)；标签失败或格式错误返回 null。 */
    fun unwrap(f: Frame): Pair<Long, Frame>? {
        if (f.serviceType != ServiceType.SECURE_WRAPPER) return null
        if (f.body.size < 8 + Crypto.TAG_LEN) return null
        if (f.body.rd16(0) != sessionId) return null
        val seq = f.body.rd48(2)
        val plain = Crypto.ccmDecrypt(encKey, nonce(seq), aad(seq), f.body.copyOfRange(8, f.body.size))
            ?: return null
        val inner = Frame.decode(plain) ?: return null
        return seq to inner
    }

    companion object {
        fun derive(sharedSecret: ByteArray, sessionId: Int): SessionCrypto {
            val encKey = Crypto.hmacSha256(sharedSecret, "session-enc".toByteArray()).copyOf(16)
            val salt = Crypto.hmacSha256(sharedSecret, "session-salt".toByteArray()).copyOf(5)
            return SessionCrypto(encKey, salt, sessionId)
        }
    }
}

/** 时间通知（组播，主干密钥 CCM 保护）：senderId(2) || timer48(6) || tag(16)。 */
object TimingMaster {
    private val SALT = byteArrayOf(0x4B, 0x4E, 0x58, 0x54, 0x4D) // "KNXTM"

    private fun nonce(senderId: Int, timer: Long) = SALT + be16(senderId) + be48(timer)

    fun tag(key: ByteArray, senderId: Int, timer: Long): ByteArray =
        Crypto.ccmEncrypt(key, nonce(senderId, timer), "timing".toByteArray(), ByteArray(0))

    fun verify(key: ByteArray, senderId: Int, timer: Long, tag: ByteArray): Boolean =
        tag.size == Crypto.TAG_LEN && Crypto.constantTimeEquals(tag(key, senderId, timer), tag)

    fun buildNotify(key: ByteArray, senderId: Int, timer: Long): Frame =
        Frame(ServiceType.TIMER_NOTIFY, be16(senderId) + be48(timer) + tag(key, senderId, timer))

    /** 返回 (senderId, timerValue, tag)。 */
    fun parseNotify(f: Frame): Triple<Int, Long, ByteArray>? {
        if (f.serviceType != ServiceType.TIMER_NOTIFY || f.body.size != 24) return null
        return Triple(f.body.rd16(0), f.body.rd48(2), f.body.copyOfRange(8, 24))
    }
}

/**
 * 组播安全封装（路由模式）：senderId(2) || timerSeq48(6) || CCM(内层帧)。
 * 序号即同步时间计数，nonce = salt(5) || senderId(2) || timerSeq48(6)。
 */
object McastWrapper {
    private val SALT = byteArrayOf(0x4B, 0x4E, 0x58, 0x4D, 0x43) // "KNXMC"

    private fun nonce(senderId: Int, timerSeq: Long) = SALT + be16(senderId) + be48(timerSeq)
    private fun aad(senderId: Int, timerSeq: Long) = be16(senderId) + be48(timerSeq)

    fun wrap(key: ByteArray, senderId: Int, timerSeq: Long, inner: Frame): Frame =
        Frame(
            ServiceType.MCAST_WRAPPER,
            aad(senderId, timerSeq) + Crypto.ccmEncrypt(key, nonce(senderId, timerSeq), aad(senderId, timerSeq), inner.encode())
        )

    /** 返回 (senderId, timerSeq, 内层帧)；标签失败返回 null。 */
    fun unwrap(key: ByteArray, f: Frame): Triple<Int, Long, Frame>? {
        if (f.serviceType != ServiceType.MCAST_WRAPPER) return null
        if (f.body.size < 8 + Crypto.TAG_LEN) return null
        val senderId = f.body.rd16(0)
        val seq = f.body.rd48(2)
        val plain = Crypto.ccmDecrypt(key, nonce(senderId, seq), aad(senderId, seq), f.body.copyOfRange(8, f.body.size))
            ?: return null
        val inner = Frame.decode(plain) ?: return null
        return Triple(senderId, seq, inner)
    }
}
