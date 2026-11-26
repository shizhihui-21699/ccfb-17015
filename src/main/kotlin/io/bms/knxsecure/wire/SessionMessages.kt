package io.bms.knxsecure.wire

import io.bms.knxsecure.util.Bytes

/**
 * A UDP/TCP endpoint, used as the identity of a session's peer.
 *
 * Session authentication frames (`0x0953`) do **not** carry the session id: the server has to
 * match them to the pending session by the datagram's source endpoint. The endpoint is
 * therefore security-relevant and is checked again on every subsequent frame.
 */
class Endpoint(address: ByteArray, val port: Int) {

    val address: ByteArray = address.copyOf()

    init {
        require(address.size == 4) { "IPv4 address must be 4 bytes" }
        require(port in 0..0xffff) { "port out of range" }
    }

    val ip: String get() = address.joinToString(".") { (it.toInt() and 0xff).toString() }

    fun toHpai(): Hpai = Hpai(Hpai.IPV4_UDP, address, port)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Endpoint) return false
        return port == other.port && address.contentEquals(other.address)
    }

    override fun hashCode(): Int = address.contentHashCode() * 31 + port

    override fun toString(): String = "$ip:$port"

    companion object {
        fun of(ip: String, port: Int): Endpoint {
            val parts = ip.split('.')
            require(parts.size == 4) { "not an IPv4 address: $ip" }
            val bytes = ByteArray(4) { i -> parts[i].toInt().toByte() }
            return Endpoint(bytes, port)
        }

        fun fromHpai(hpai: Hpai, fallbackPort: Int = hpai.port): Endpoint =
            Endpoint(hpai.address, fallbackPort)
    }
}

/** Decoded `0x0951` secure session request. */
data class SessionRequest(val clientHpai: Hpai, val clientPublicKey: ByteArray) {
    init {
        require(clientPublicKey.size == 32) { "client X25519 public key must be 32 bytes" }
    }

    override fun equals(other: Any?): Boolean =
        other is SessionRequest && clientHpai == other.clientHpai &&
            clientPublicKey.contentEquals(other.clientPublicKey)

    override fun hashCode(): Int = clientHpai.hashCode() * 31 + clientPublicKey.contentHashCode()
}

/** Decoded `0x0952` secure session response (server -> client). */
data class SessionResponse(
    val sessionId: Int,
    val serverPublicKey: ByteArray?,
    val mac: ByteArray?,
) {
    init {
        require(sessionId in 0..0xffff) { "session id out of range" }
        if (serverPublicKey != null) require(serverPublicKey.size == 32) { "server public key must be 32 bytes" }
        if (mac != null) require(mac.size == 16) { "mac must be 16 bytes" }
    }

    val isBusy: Boolean get() = sessionId == 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SessionResponse) return false
        return sessionId == other.sessionId &&
            (serverPublicKey?.contentEquals(other.serverPublicKey ?: ByteArray(0)) ?: (other.serverPublicKey == null)) &&
            (mac?.contentEquals(other.mac ?: ByteArray(0)) ?: (other.mac == null))
    }

    override fun hashCode(): Int {
        var r = sessionId
        r = 31 * r + (serverPublicKey?.contentHashCode() ?: 0)
        r = 31 * r + (mac?.contentHashCode() ?: 0)
        return r
    }
}

/** Decoded `0x0953` secure session authentication (client -> server). */
data class SessionAuth(val userId: Int, val mac: ByteArray) {
    init {
        require(userId in 0..0xffff) { "user id out of range" }
        require(mac.size == 16) { "mac must be 16 bytes" }
    }

    override fun equals(other: Any?): Boolean =
        other is SessionAuth && userId == other.userId && mac.contentEquals(other.mac)

    override fun hashCode(): Int = userId * 31 + mac.contentHashCode()
}

/** Session status codes carried inside a wrapped `0x0954` frame. */
enum class SessionStatus(val code: Int) {
    AUTH_SUCCESS(0),
    AUTH_FAILED(1),
    UNAUTHORIZED(2),
    TIMEOUT(3),
    KEEP_ALIVE(4),
    CLOSE(5);

    companion object {
        fun of(code: Int): SessionStatus? = entries.firstOrNull { it.code == code }
    }
}

/**
 * Encoders/decoders for the session-establishment services.
 *
 * None of these messages is authenticated by itself; the MACs are computed by
 * [SessionHandshake] so that the exact input assembly lives in one auditable place.
 */
object SessionMessages {

    const val PUBLIC_KEY_BYTES = 32
    const val MAC_BYTES = 16

    fun encodeRequest(hpai: Hpai, clientPublicKey: ByteArray): ByteArray {
        require(clientPublicKey.size == PUBLIC_KEY_BYTES) { "client public key must be 32 bytes" }
        val body = Bytes.concat(hpai.encode(), clientPublicKey)
        return Bytes.concat(KnxIpHeader(ServiceType.SECURE_SESSION_REQUEST, KnxIpHeader.HEADER_BYTES + body.size).encode(), body)
    }

    fun decodeRequest(frame: ByteArray, offset: Int = 0): SessionRequest {
        val header = KnxIpHeader.decode(frame, offset)
        if (header.serviceType != ServiceType.SECURE_SESSION_REQUEST) {
            throw ProtocolFormatException("not a session request: ${ServiceType.name(header.serviceType)}")
        }
        val p = offset + KnxIpHeader.HEADER_BYTES
        if (header.bodyLength != Hpai.SIZE + PUBLIC_KEY_BYTES) {
            throw ProtocolFormatException("session request body must be 40 bytes, got ${header.bodyLength}")
        }
        val hpai = Hpai.decode(frame, p)
        val key = frame.copyOfRange(p + Hpai.SIZE, p + Hpai.SIZE + PUBLIC_KEY_BYTES)
        return SessionRequest(hpai, key)
    }

    fun encodeResponse(sessionId: Int, serverPublicKey: ByteArray, maskedMac: ByteArray): ByteArray {
        require(serverPublicKey.size == PUBLIC_KEY_BYTES) { "server public key must be 32 bytes" }
        require(maskedMac.size == MAC_BYTES) { "mac must be 16 bytes" }
        val body = Bytes.concat(Bytes.encodeU16(sessionId), serverPublicKey, maskedMac)
        return Bytes.concat(KnxIpHeader(ServiceType.SECURE_SESSION_RESPONSE, KnxIpHeader.HEADER_BYTES + body.size).encode(), body)
    }

    /** Response sent when no channel is free: header + 16-bit session id 0. */
    fun encodeBusyResponse(): ByteArray =
        Bytes.concat(KnxIpHeader(ServiceType.SECURE_SESSION_RESPONSE, KnxIpHeader.HEADER_BYTES + 2).encode(), Bytes.encodeU16(0))

    fun decodeResponse(frame: ByteArray, offset: Int = 0): SessionResponse {
        val header = KnxIpHeader.decode(frame, offset)
        if (header.serviceType != ServiceType.SECURE_SESSION_RESPONSE) {
            throw ProtocolFormatException("not a session response")
        }
        if (header.bodyLength != 2 && header.bodyLength != 2 + PUBLIC_KEY_BYTES + MAC_BYTES) {
            throw ProtocolFormatException("invalid session response body length ${header.bodyLength}")
        }
        val p = offset + KnxIpHeader.HEADER_BYTES
        val sessionId = Bytes.u16(frame, p)
        if (header.bodyLength == 2) return SessionResponse(sessionId, null, null)
        val pub = frame.copyOfRange(p + 2, p + 2 + PUBLIC_KEY_BYTES)
        val mac = frame.copyOfRange(p + 2 + PUBLIC_KEY_BYTES, p + 2 + PUBLIC_KEY_BYTES + MAC_BYTES)
        return SessionResponse(sessionId, pub, mac)
    }

    fun encodeAuth(userId: Int, maskedMac: ByteArray): ByteArray {
        require(maskedMac.size == MAC_BYTES) { "mac must be 16 bytes" }
        val body = Bytes.concat(Bytes.encodeU16(userId), maskedMac)
        return Bytes.concat(KnxIpHeader(ServiceType.SECURE_SESSION_AUTH, KnxIpHeader.HEADER_BYTES + body.size).encode(), body)
    }

    fun decodeAuth(frame: ByteArray, offset: Int = 0): SessionAuth {
        val header = KnxIpHeader.decode(frame, offset)
        if (header.serviceType != ServiceType.SECURE_SESSION_AUTH) {
            throw ProtocolFormatException("not a session auth")
        }
        if (header.bodyLength != 2 + MAC_BYTES) {
            throw ProtocolFormatException("session auth body must be 18 bytes, got ${header.bodyLength}")
        }
        val p = offset + KnxIpHeader.HEADER_BYTES
        return SessionAuth(Bytes.u16(frame, p), frame.copyOfRange(p + 2, p + 2 + MAC_BYTES))
    }

    /** Builds the inner (unwrapped) `0x0954` session-status packet. */
    fun encodeStatusInner(status: SessionStatus): ByteArray {
        val body = byteArrayOf(status.code.toByte(), 0)
        return Bytes.concat(KnxIpHeader(ServiceType.SECURE_SESSION_STATUS, KnxIpHeader.HEADER_BYTES + body.size).encode(), body)
    }

    /** Returns the status carried by a decrypted inner packet, or null if it is not a status. */
    fun decodeStatusInner(inner: ByteArray, offset: Int = 0): SessionStatus? {
        if (inner.size - offset < KnxIpHeader.HEADER_BYTES + 1) return null
        val header = KnxIpHeader.decode(inner, offset)
        if (header.serviceType != ServiceType.SECURE_SESSION_STATUS) return null
        return SessionStatus.of(Bytes.u8(inner, offset + KnxIpHeader.HEADER_BYTES))
    }
}
