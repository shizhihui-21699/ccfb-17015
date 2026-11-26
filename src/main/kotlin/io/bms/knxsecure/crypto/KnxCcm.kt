package io.bms.knxsecure.crypto

import io.bms.knxsecure.util.Bytes
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

/**
 * The AES-CCM profile used by the KNX IP Secure wrapper.
 *
 * KNX IP Secure protects a frame with a 128-bit authentication tag and AES-CTR style
 * encryption (the CCM construction: CBC-MAC for authenticity, counter mode for
 * confidentiality, tag masked with the zeroth counter block).
 *
 * The exact byte layout differs from RFC 3610 CCM: KNX derives a 16-byte *security info*
 * block from the 48-bit sequence number (unicast) or group timestamp (multicast), the 6-byte
 * sender serial number, the 16-bit message tag and a 16-bit length field:
 *
 * ```
 * secInfo = seq/timestamp(6) || serialNumber(6) || messageTag(2) || lengthField(2)
 * ```
 *
 * It then CBC-MACs
 *
 * ```
 * secInfo(16) || {0x00, 6 + sessionLen} || outerHeader(6) || sessionId(0|2) || containedFrame || 0x00*
 * ```
 *
 * with AES-CBC and a zero IV and takes the last 16 bytes as the tag. Confidentiality is
 * CCM counter mode: the tag is XORed with keystream block S0 and the contained frame with
 * S1..Sn.
 *
 * Everything here was validated byte-for-byte against reference KNX IP Secure frames
 * (see `KnxCcmVectorsTest`), because interoperability is the reason the format exists.
 */
object KnxCcm {

    const val TAG_BYTES = 16
    const val BLOCK_BYTES = 16

    /** Cipher instances are not thread safe; keep one per thread. */
    private val ecb: ThreadLocal<Cipher> = ThreadLocal.withInitial { Cipher.getInstance("AES/ECB/NoPadding") }
    private val cbc: ThreadLocal<Cipher> = ThreadLocal.withInitial { Cipher.getInstance("AES/CBC/NoPadding") }

    /**
     * Builds the 16-byte security-info block.
     *
     * @param sequence 48-bit unicast sequence number, or 48-bit group timestamp
     * @param serialNumber 48-bit sender serial number
     * @param messageTag 16-bit message tag
     * @param lengthField MAC: contained-frame byte length; keystream: `0xff00`
     */
    fun securityInfo(sequence: Long, serialNumber: Long, messageTag: Int, lengthField: Int): ByteArray {
        require(sequence in 0..Bytes.MAX_U48) { "48-bit value out of range: $sequence" }
        require(serialNumber in 0..Bytes.MAX_U48) { "48-bit serial number out of range: $serialNumber" }
        require(messageTag in 0..0xffff) { "message tag out of range: $messageTag" }
        require(lengthField in 0..0xffff) { "length field out of range: $lengthField" }
        val info = ByteArray(16)
        Bytes.putU48(info, 0, sequence)
        Bytes.putU48(info, 6, serialNumber)
        Bytes.putU16(info, 12, messageTag)
        Bytes.putU16(info, 14, lengthField)
        return info
    }

    /**
     * CBC-MAC over arbitrary bytes with a zero IV, zero padded to a block multiple, returning
     * the trailing 16 bytes. Used for the handshake authentication codes.
     */
    fun cbcMacZeroPad(key: AesKey, data: ByteArray): ByteArray {
        val padded = if (data.size % BLOCK_BYTES == 0) data.copyOf() else data.copyOf(roundUp(data.size))

        val cipher = cbc.get()
        cipher.init(Cipher.ENCRYPT_MODE, key.secretKey(), IvParameterSpec(ByteArray(BLOCK_BYTES)))
        val out = cipher.doFinal(padded)
        return out.copyOfRange(out.size - TAG_BYTES, out.size)
    }

    /**
     * The KNX CBC-MAC over a secure frame (wrapper or group-sync).
     *
     * @param secInfo security-info block built for the MAC (length field = frame length)
     * @param outerHeader the 6-byte KNXnet/IP header of the secure frame
     * @param sessionId the 2-byte session id, or null for multicast frames (field absent)
     * @param frame the contained KNXnet/IP packet (may be empty for a bare MAC frame)
     */
    fun mac(key: AesKey, secInfo: ByteArray, outerHeader: ByteArray, sessionId: ByteArray?, frame: ByteArray): ByteArray {
        require(secInfo.size == 16) { "secInfo must be 16 bytes" }
        require(outerHeader.size == 6) { "KNXnet/IP header must be 6 bytes" }
        val sessionLen = sessionId?.size ?: 0
        require(sessionLen == 0 || sessionLen == 2) { "session id must be 2 bytes or absent" }

        val checkLength = 16 + 2 + 6 + sessionLen + frame.size
        // KNX pads the contained frame so that the CBC input becomes a block multiple.
        // This is the specification's formula, including its behaviour at block boundaries.
        val paddedLen = frame.size + 15 - (checkLength + 15) % BLOCK_BYTES
        require(paddedLen >= frame.size) { "internal padding error" }

        val input = ByteArray(16 + 2 + 6 + sessionLen + paddedLen)
        var o = 0
        System.arraycopy(secInfo, 0, input, o, 16); o += 16
        input[o++] = 0
        input[o++] = (6 + sessionLen).toByte()
        System.arraycopy(outerHeader, 0, input, o, 6); o += 6
        if (sessionLen == 2) {
            System.arraycopy(sessionId!!, 0, input, o, 2); o += 2
        }
        System.arraycopy(frame, 0, input, o, frame.size) // remaining bytes are zero
        require(input.size % BLOCK_BYTES == 0) { "CBC input not block aligned: ${input.size}" }

        val cipher = cbc.get()
        cipher.init(Cipher.ENCRYPT_MODE, key.secretKey(), IvParameterSpec(ByteArray(BLOCK_BYTES)))
        val out = cipher.doFinal(input)
        return out.copyOfRange(out.size - TAG_BYTES, out.size)
    }

    /**
     * Applies the CCM counter-mode mask: the trailing 16-byte tag is XORed with S0 and the
     * preceding payload bytes with S1..Sn. Encryption and decryption are the same operation.
     *
     * @param data payload followed by the 16-byte tag (total length >= 16)
     * @param secInfo counter-block prefix; its last byte is incremented per block, exactly as
     *        the reference implementation does
     */
    fun mask(key: AesKey, data: ByteArray, secInfo: ByteArray): ByteArray {
        require(secInfo.size == 16) { "secInfo must be 16 bytes" }
        require(data.size >= TAG_BYTES) { "masked region must contain at least a tag" }
        val blocks = (data.size + BLOCK_BYTES - 1) / BLOCK_BYTES
        require(blocks <= 256) {
            // The counter lives in a single byte in the KNX construction. Real KNX frames are
            // far smaller; refusing is safer than silently reusing keystream.
            "frame too large for the KNX counter block: $blocks blocks"
        }

        val stream = ByteArray(blocks * BLOCK_BYTES)
        val counter = secInfo.copyOf()
        val cipher = ecb.get()
        cipher.init(Cipher.ENCRYPT_MODE, key.secretKey())
        for (i in 0 until blocks) {
            val block = cipher.doFinal(counter)
            System.arraycopy(block, 0, stream, i * BLOCK_BYTES, BLOCK_BYTES)
            counter[15] = (counter[15].toInt() + 1).toByte()
        }

        val out = ByteArray(data.size)
        if (blocks > 1) {
            val payloadLen = data.size - TAG_BYTES
            for (i in 0 until payloadLen) out[i] = (data[i].toInt() xor stream[TAG_BYTES + i].toInt()).toByte()
            for (i in 0 until TAG_BYTES) out[payloadLen + i] =
                (data[payloadLen + i].toInt() xor stream[i].toInt()).toByte()
        } else {
            for (i in data.indices) out[i] = (data[i].toInt() xor stream[i].toInt()).toByte()
        }
        return out
    }

    /**
     * Masks/unmasks the 16-byte authentication code of a handshake frame, whose security
     * info is 14 zero bytes followed by `0xff00`.
     */
    fun maskTag(key: AesKey, tag: ByteArray): ByteArray {
        require(tag.size == TAG_BYTES) { "tag must be 16 bytes" }
        val secInfo = ByteArray(16)
        secInfo[14] = 0xff.toByte()
        secInfo[15] = 0x00
        return mask(key, tag, secInfo)
    }

    private fun roundUp(n: Int): Int = (n + BLOCK_BYTES - 1) / BLOCK_BYTES * BLOCK_BYTES
}
