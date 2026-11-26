package io.bms.knxsecure.wire

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.ProtocolException
import io.bms.knxsecure.util.Bytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Interoperability tests.
 *
 * Every expected frame below was produced by the reference KNX IP Secure implementation
 * (calimero-core 3.0-M1, `SecureConnection.newSecurePacket`). Matching them byte for byte is
 * what proves this gateway can talk to real panels and ETS.
 */
class WireInteropTest {

    private val key = AesKey.of(Bytes.unhex("000102030405060708090a0b0c0d0e0f"))
    private val verifier = SecureFrameVerifier()
    private val payload = Bytes.unhex("06100530000d00aabbccddeeff")

    @Test
    fun `unicast wrapper matches reference`() {
        val expected = Bytes.unhex(
            "061009500033123400010203040500112233445500ab886b95bb52d8ff4c9294c32f425b6d201a0a5223f9cec5997efb87aa6f"
        )
        val actual = SecureFrames.wrap(key, 0x1234, 0x000102030405L, 0x001122334455L, 0x00ab, payload)
        assertContentEquals(expected, actual)
    }

    @Test
    fun `unicast wrapper with maximum sequence and tag matches reference`() {
        val expected = Bytes.unhex(
            "0610095000330000ffffffffffff010203040506ffffc6db36aa13f7c75beac9f518cbc27c23a699c009cdeb22254f3a078d58"
        )
        val actual = SecureFrames.wrap(key, 0, 0xffffffffffffL, 0x010203040506L, 0xffff, payload)
        assertContentEquals(expected, actual)
    }

    @Test
    fun `wrapper with a full bank of blocks matches reference`() {
        val payload3 = ByteArray(40) { (0x30 + it).toByte() }
        val expected = Bytes.unhex(
            "06100950004e000100000000002adeadbeef00010007" +
                "eef0f19d375cf25c3e2efba0e6f660cbe83e1719f4740723442a575c928ac281b3c2b55f27cfe6146a2e18a07ca0f2d99e4d7a91d463bf22"
        )
        val actual = SecureFrames.wrap(key, 0x0001, 42L, 0xdeadbeef0001L, 7, payload3)
        assertContentEquals(expected, actual)
    }

    @Test
    fun `multicast wrapper matches reference`() {
        val expected = Bytes.unhex(
            "0610095000330000017f2a5c3b21001122334455beefa5ba4e2262260ee1093c50a3090880a8faebc3f3e7cd481df2e0ded7f6"
        )
        val actual = SecureFrames.wrapMulticast(key, 0x0000017f2a5c3b21L, 0x001122334455L, 0xbeef, payload)
        assertContentEquals(expected, actual)
    }

    @Test
    fun `group sync frame matches reference`() {
        val expected = Bytes.unhex("061009550024017f2a5c3b21001122334455beef2159e5ce419654577e69e98960723bda")
        val actual = SecureFrames.groupSync(key, 0x0000017f2a5c3b21L, 0x001122334455L, 0xbeef)
        assertContentEquals(expected, actual)
    }

    @Test
    fun `verifier accepts reference frames and recovers fields`() {
        val frame = Bytes.unhex(
            "061009500033123400010203040500112233445500ab886b95bb52d8ff4c9294c32f425b6d201a0a5223f9cec5997efb87aa6f"
        )
        val w = verifier.openWrapper(key, frame)
        assertEquals(0x1234, w.sessionId)
        assertEquals(0x000102030405L, w.sequence)
        assertEquals(0x001122334455L, w.serialNumber)
        assertEquals(0x00ab, w.messageTag)
        assertContentEquals(payload, w.payload)
        assertFalse(w.isMulticast)
    }

    @Test
    fun `verifier accepts reference group sync and recovers timestamp`() {
        val frame = Bytes.unhex("061009550024017f2a5c3b21001122334455beef2159e5ce419654577e69e98960723bda")
        val gs = verifier.openGroupSync(key, frame)
        assertEquals(0x0000017f2a5c3b21L, gs.timestamp)
        assertEquals(0x001122334455L, gs.serialNumber)
        assertEquals(0xbeef, gs.messageTag)
    }

    @Test
    fun `tampering with any authenticated field is detected`() {
        val frame = Bytes.unhex(
            "061009500033123400010203040500112233445500ab886b95bb52d8ff4c9294c32f425b6d201a0a5223f9cec5997efb87aa6f"
        )
        // Flip a bit in the sequence number: MAC must fail.
        val tamperedSeq = frame.copyOf().also { it[9] = (it[9].toInt() xor 0x01).toByte() }
        assertFailsWith<MacVerificationException> { verifier.openWrapper(key, tamperedSeq) }
        // Flip a bit in the ciphertext.
        val tamperedPayload = frame.copyOf().also { it[30] = (it[30].toInt() xor 0x80).toByte() }
        assertFailsWith<MacVerificationException> { verifier.openWrapper(key, tamperedPayload) }
        // Wrong key.
        val wrong = AesKey.of(ByteArray(16) { 7 })
        assertFailsWith<MacVerificationException> { verifier.openWrapper(wrong, frame) }
    }

    @Test
    fun `truncated and malformed frames are rejected before authentication`() {
        assertFailsWith<ProtocolFormatException> { verifier.openWrapper(key, ByteArray(10)) }
        val badTotal = Bytes.unhex("06100950ffff") + ByteArray(10)
        assertFailsWith<ProtocolFormatException> { verifier.openWrapper(key, badTotal) }
    }

    @Test
    fun `wrong service type is rejected`() {
        val frame = Bytes.unhex("061005300006") // routing.ind header, too short for a session
        assertFailsWith<ProtocolException> { verifier.openWrapper(key, frame) }
    }

    @Test
    fun `session status and data frames decrypt to expected inner packets`() {
        val sessionKey = AesKey.of(Bytes.unhex("dead45a1d43d6902aa9240b43c0d75a0"))
        val status = Bytes.unhex("06100950002e424200000000000001020304050600004b4bdd8226d91f169f24d5f1a062edaac8f25efa660278f7")
        val w1 = verifier.openWrapper(sessionKey, status)
        assertEquals(SessionStatus.AUTH_SUCCESS, SessionMessages.decodeStatusInner(w1.payload))
        assertEquals(0L, w1.sequence)

        val data = Bytes.unhex(
            "06100950003a4242000000000001010203040506000055b2215c716968c094f0946211950b79c309b106a941d8ead6a3e36afae8700af0f5cefb"
        )
        val w2 = verifier.openWrapper(sessionKey, data)
        assertEquals(1L, w2.sequence)
        assertEquals(0x0420, KnxIpHeader.decode(w2.payload).serviceType)
        assertEquals(20, w2.payload.size)
    }

    @Test
    fun `group sync rejects a wrong key`() {
        val frame = Bytes.unhex("061009550024017f2a5c3b21001122334455beef2159e5ce419654577e69e98960723bda")
        assertFailsWith<MacVerificationException> { verifier.openGroupSync(AesKey.of(ByteArray(16) { 9 }), frame) }
    }

    @Test
    fun `round trip through wrap and verify`() {
        val payload = ByteArray(33) { (it * 7).toByte() }
        val frame = SecureFrames.wrap(key, 7, 12345, 0xabcdef012345L, 99, payload)
        val w = verifier.openWrapper(key, frame)
        assertEquals(7, w.sessionId)
        assertEquals(12345, w.sequence)
        assertEquals(0xabcdef012345L, w.serialNumber)
        assertEquals(99, w.messageTag)
        assertContentEquals(payload, w.payload)
    }

    @Test
    fun `max sequence value is encodable at the codec layer`() {
        // Sequence-renewal policy is enforced by the session layer; the codec must faithfully
        // encode the whole 48-bit range (the reference implementation does the same).
        val frame = SecureFrames.wrap(key, 1, Bytes.MAX_U48, 1, 0, payload)
        assertEquals(Bytes.MAX_U48, verifier.openWrapper(key, frame).sequence)
    }

    @Test
    fun `header roundtrip`() {
        val h = KnxIpHeader(ServiceType.SECURE_WRAPPER, 42)
        val decoded = KnxIpHeader.decode(h.encode() + ByteArray(36))
        assertEquals(h, decoded)
        assertTrue(decoded.bodyLength == 36)
    }
}
