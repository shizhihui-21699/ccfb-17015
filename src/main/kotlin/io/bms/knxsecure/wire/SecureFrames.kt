package io.bms.knxsecure.wire

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxCcm
import io.bms.knxsecure.util.Bytes

/**
 * A decoded KNX IP Secure wrapper frame (`0x0950`).
 *
 * Wire layout after the 6-byte KNXnet/IP header:
 * ```
 * sessionId(2) | seq(6) | serialNumber(6) | messageTag(2) | payload | tag(16)
 * ```
 * The session-id field is always present on the wire; multicast wrappers set it to 0 and
 * the sequence field carries the 48-bit group timestamp instead of a counter.
 */
data class SecureWrapper(
    val sessionId: Int,
    val sequence: Long,
    val serialNumber: Long,
    val messageTag: Int,
    val payload: ByteArray,
    val tag: ByteArray,
) {
    init {
        require(sessionId in 0..0xffff) { "session id out of range" }
        require(sequence in 0..Bytes.MAX_U48) { "sequence out of range" }
        require(serialNumber in 0..Bytes.MAX_U48) { "serial number out of range" }
        require(messageTag in 0..0xffff) { "message tag out of range" }
        require(tag.size == KnxCcm.TAG_BYTES) { "tag must be 16 bytes" }
    }

    /** KNX multicast (routing) frames use session id 0. */
    val isMulticast: Boolean get() = sessionId == 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecureWrapper) return false
        return sessionId == other.sessionId && sequence == other.sequence &&
            serialNumber == other.serialNumber && messageTag == other.messageTag &&
            payload.contentEquals(other.payload) && tag.contentEquals(other.tag)
    }

    override fun hashCode(): Int {
        var r = sessionId
        r = 31 * r + sequence.hashCode()
        r = 31 * r + serialNumber.hashCode()
        r = 31 * r + messageTag
        r = 31 * r + payload.contentHashCode()
        r = 31 * r + tag.contentHashCode()
        return r
    }

    override fun toString(): String =
        "SecureWrapper(session=$sessionId, seq=$sequence, sn=${"%06x".format(serialNumber)}, " +
            "tag=$messageTag, payload=${payload.size}B, mac=${Bytes.hex(tag)})"
}

/**
 * A decoded KNX IP Secure group-sync / timer-notify frame (`0x0955`).
 *
 * Wire layout: `timestamp(6) | serialNumber(6) | messageTag(2) | mac(16)`.
 *
 * The group timestamp is the time base that every device on the multicast segment uses to
 * judge whether a secure routing frame is fresh. It is authenticated only with the shared
 * backbone group key, so a single forged announcement can shift the whole segment's notion
 * of "now". The gateway must therefore treat this value as hostile input and cross-check it
 * against local monotonic time and peer diversity (see `TimeSyncGuard`), never as an
 * authoritative clock.
 */
data class GroupSync(
    val timestamp: Long,
    val serialNumber: Long,
    val messageTag: Int,
    val mac: ByteArray,
) {
    init {
        require(timestamp in 0..Bytes.MAX_U48) { "timestamp out of range" }
        require(serialNumber in 0..Bytes.MAX_U48) { "serial number out of range" }
        require(messageTag in 0..0xffff) { "message tag out of range" }
        require(mac.size == KnxCcm.TAG_BYTES) { "mac must be 16 bytes" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GroupSync) return false
        return timestamp == other.timestamp && serialNumber == other.serialNumber &&
            messageTag == other.messageTag && mac.contentEquals(other.mac)
    }

    override fun hashCode(): Int {
        var r = timestamp.hashCode()
        r = 31 * r + serialNumber.hashCode()
        r = 31 * r + messageTag
        r = 31 * r + mac.contentHashCode()
        return r
    }
}

/**
 * Encodes secure frames.
 *
 * Encoding is pure and thread-safe. Decoding and verification live in
 * [SecureFrameVerifier] so the "authenticate before you act" ordering is explicit.
 */
object SecureFrames {

    /** sessionId + seq + serial + tag + mac */
    const val WRAPPER_FIXED_BODY = 2 + 6 + 6 + 2 + KnxCcm.TAG_BYTES
    const val GROUP_SYNC_BODY = 6 + 6 + 2 + KnxCcm.TAG_BYTES

    fun wrap(
        key: AesKey,
        sessionId: Int,
        sequence: Long,
        serialNumber: Long,
        messageTag: Int,
        payload: ByteArray,
    ): ByteArray {
        require(sessionId in 0..0xffff) { "session id out of range" }
        require(sequence in 0..Bytes.MAX_U48) { "sequence out of range" }
        require(messageTag in 0..0xffff) { "message tag out of range" }

        val header = KnxIpHeader(
            ServiceType.SECURE_WRAPPER,
            KnxIpHeader.HEADER_BYTES + WRAPPER_FIXED_BODY + payload.size,
        ).encode()

        val sessionField = Bytes.encodeU16(sessionId)
        val macInfo = KnxCcm.securityInfo(sequence, serialNumber, messageTag, payload.size)
        val tag = KnxCcm.mac(key, macInfo, header, sessionField, payload)

        val keystreamInfo = KnxCcm.securityInfo(sequence, serialNumber, messageTag, 0xff00)
        val encRegion = KnxCcm.mask(key, Bytes.concat(payload, tag), keystreamInfo)

        return Bytes.concat(
            header,
            sessionField,
            Bytes.encodeU48(sequence),
            Bytes.encodeU48(serialNumber),
            Bytes.encodeU16(messageTag),
            encRegion,
        )
    }

    /** Convenience for multicast (routing) wrappers: session id 0, sequence field = timestamp. */
    fun wrapMulticast(
        key: AesKey,
        timestamp: Long,
        serialNumber: Long,
        messageTag: Int,
        payload: ByteArray,
    ): ByteArray = wrap(key, 0, timestamp, serialNumber, messageTag, payload)

    /**
     * Builds a group-sync frame.
     *
     * Note the unusual layout: the header declares a 0x1e body, but the MAC covers only the
     * 14-byte timestamp/serial/tag prefix plus the header, and the 16-byte MAC is itself
     * counter-mode encrypted with a security-info block derived from that same prefix.
     */
    fun groupSync(key: AesKey, timestamp: Long, serialNumber: Long, messageTag: Int): ByteArray {
        require(timestamp in 0..Bytes.MAX_U48) { "timestamp out of range" }
        require(messageTag in 0..0xffff) { "message tag out of range" }

        val header = KnxIpHeader(
            ServiceType.SECURE_GROUP_SYNC,
            KnxIpHeader.HEADER_BYTES + GROUP_SYNC_BODY,
        ).encode()
        val macInfo = KnxCcm.securityInfo(timestamp, serialNumber, messageTag, 0)
        val mac = KnxCcm.mac(key, macInfo, header, null, ByteArray(0))
        val keystreamInfo = KnxCcm.securityInfo(timestamp, serialNumber, messageTag, 0xff00)
        val masked = KnxCcm.mask(key, mac, keystreamInfo)

        return Bytes.concat(
            header,
            Bytes.encodeU48(timestamp),
            Bytes.encodeU48(serialNumber),
            Bytes.encodeU16(messageTag),
            masked,
        )
    }
}

/** Serial number helpers (48-bit device identity, usually derived from the MAC address). */
object SerialNumbers {
    fun random(): Long = java.security.SecureRandom().nextLong() and Bytes.MAX_U48

    fun fromMac(mac: ByteArray): Long {
        require(mac.size >= 6) { "MAC must have at least 6 bytes" }
        return Bytes.u48(mac, 0)
    }

    fun format(sn: Long): String = "%012x".format(sn)
}
