package io.bms.knxsecure.wire

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxCcm
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.ProtocolException
import io.bms.knxsecure.util.Bytes

/**
 * Decodes and authenticates secure frames.
 *
 * Ordering is deliberate and enforced here: **parse structure, then authenticate, then
 * release plaintext**. No caller can obtain a payload without a passing MAC, and the MAC
 * covers the header, session id and sequence number, so none of those fields can be
 * tampered with.
 */
class SecureFrameVerifier {

    /**
     * Verifies and decrypts a `0x0950` wrapper.
     *
     * @throws ProtocolException on malformed structure
     * @throws MacVerificationException if the authentication tag does not verify
     */
    fun openWrapper(key: AesKey, frame: ByteArray, offset: Int = 0): SecureWrapper {
        val header = KnxIpHeader.decode(frame, offset)
        if (header.serviceType != ServiceType.SECURE_WRAPPER) {
            throw ProtocolException("not a secure wrapper: ${ServiceType.name(header.serviceType)}")
        }
        val body = header.bodyLength
        if (body < SecureFrames.WRAPPER_FIXED_BODY) {
            throw ProtocolException("secure wrapper body $body shorter than minimum ${SecureFrames.WRAPPER_FIXED_BODY}")
        }

        var p = offset + KnxIpHeader.HEADER_BYTES
        val sessionId = Bytes.u16(frame, p); p += 2
        val sequence = Bytes.u48(frame, p); p += 6
        val serialNumber = Bytes.u48(frame, p); p += 6
        val messageTag = Bytes.u16(frame, p); p += 2
        val payloadLen = body - SecureFrames.WRAPPER_FIXED_BODY
        val encRegion = frame.copyOfRange(p, p + payloadLen + KnxCcm.TAG_BYTES)

        // Rebuild the exact plaintext/MAC inputs from the received (authenticated-part) fields.
        val headerBytes = frame.copyOfRange(offset, offset + KnxIpHeader.HEADER_BYTES)
        val sessionField = frame.copyOfRange(offset + KnxIpHeader.HEADER_BYTES, offset + KnxIpHeader.HEADER_BYTES + 2)
        val macInfo = KnxCcm.securityInfo(sequence, serialNumber, messageTag, payloadLen)
        val keystreamInfo = KnxCcm.securityInfo(sequence, serialNumber, messageTag, 0xff00)

        val decrypted = KnxCcm.mask(key, encRegion, keystreamInfo)
        val payload = decrypted.copyOfRange(0, payloadLen)
        val tag = decrypted.copyOfRange(payloadLen, decrypted.size)

        val expected = KnxCcm.mac(key, macInfo, headerBytes, sessionField, payload)
        if (!Bytes.constantTimeEquals(expected, tag)) {
            throw MacVerificationException(
                "secure wrapper MAC mismatch (session=$sessionId seq=$sequence sn=${SerialNumbers.format(serialNumber)})"
            )
        }
        return SecureWrapper(sessionId, sequence, serialNumber, messageTag, payload, tag)
    }

    /**
     * Verifies and unmasks a `0x0955` group-sync frame.
     *
     * @throws ProtocolException on malformed structure
     * @throws MacVerificationException if the frame was not produced by a holder of the group key
     */
    fun openGroupSync(key: AesKey, frame: ByteArray, offset: Int = 0): GroupSync {
        val header = KnxIpHeader.decode(frame, offset)
        if (header.serviceType != ServiceType.SECURE_GROUP_SYNC) {
            throw ProtocolException("not a group-sync frame: ${ServiceType.name(header.serviceType)}")
        }
        if (header.totalLength != KnxIpHeader.HEADER_BYTES + SecureFrames.GROUP_SYNC_BODY) {
            throw ProtocolException("group-sync frame must be exactly 0x24 bytes, got ${header.totalLength}")
        }

        var p = offset + KnxIpHeader.HEADER_BYTES
        val timestamp = Bytes.u48(frame, p); p += 6
        val serialNumber = Bytes.u48(frame, p); p += 6
        val messageTag = Bytes.u16(frame, p); p += 2
        val maskedMac = frame.copyOfRange(p, p + KnxCcm.TAG_BYTES)

        val keystreamInfo = KnxCcm.securityInfo(timestamp, serialNumber, messageTag, 0xff00)
        val mac = KnxCcm.mask(key, maskedMac, keystreamInfo)

        val headerBytes = frame.copyOfRange(offset, offset + KnxIpHeader.HEADER_BYTES)
        val macInfo = KnxCcm.securityInfo(timestamp, serialNumber, messageTag, 0)
        val expected = KnxCcm.mac(key, macInfo, headerBytes, null, ByteArray(0))
        if (!Bytes.constantTimeEquals(expected, mac)) {
            throw MacVerificationException("group-sync MAC mismatch (sn=${SerialNumbers.format(serialNumber)})")
        }
        return GroupSync(timestamp, serialNumber, messageTag, mac)
    }
}
