package io.bms.knxsecure.session

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxSecureException
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.Pbkdf2
import io.bms.knxsecure.crypto.X25519
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.wire.Hpai
import io.bms.knxsecure.wire.SessionMessages
import io.bms.knxsecure.wire.SessionStatus
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Session handshake known answers and negative cases.
 *
 * The golden values use the RFC 7748 Alice/Bob key pairs so the X25519 half is independently
 * verifiable, and the MACs were cross-checked against the reference KNX implementation.
 */
class SessionHandshakeTest {

    private val clientPriv = Bytes.unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private val clientPub = Bytes.unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    private val serverPriv = Bytes.unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    private val serverPub = Bytes.unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

    private val userKey = AesKey.of(Pbkdf2.userKey("password"))
    private val deviceKey = AesKey.of(Pbkdf2.deviceAuthKey("device-pw"))

    @Test
    fun `session key derivation matches reference`() {
        val shared = X25519.agree(clientPriv, serverPub)
        assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", Bytes.hex(shared))
        assertEquals("dead45a1d43d6902aa9240b43c0d75a0", Bytes.hex(SessionHandshake.deriveSessionKey(shared)))
    }

    @Test
    fun `session response MAC matches reference`() {
        val mac = SessionHandshake.sessionResponseMac(deviceKey, serverPub, clientPub, 0x4242)
        assertEquals("6ab3632a2c311cd3992f6f16e4704678", Bytes.hex(mac))
        assertEquals("262d7d328b77e2946f21c361c327c104", Bytes.hex(SessionHandshake.mask(deviceKey, mac)))
    }

    @Test
    fun `session auth MAC matches reference`() {
        val mac = SessionHandshake.sessionAuthMac(userKey, serverPub, clientPub, 7)
        assertEquals("79143ba86113de82ac118ce80b296098", Bytes.hex(mac))
        assertEquals("71d92c0b6d8e180cc70180708e91f92e", Bytes.hex(SessionHandshake.mask(userKey, mac)))
    }

    @Test
    fun `encoded session messages match reference bytes`() {
        val responseMac = SessionHandshake.mask(
            deviceKey, SessionHandshake.sessionResponseMac(deviceKey, serverPub, clientPub, 0x4242),
        )
        assertEquals(
            "0610095200384242de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f262d7d328b77e2946f21c361c327c104",
            Bytes.hex(SessionMessages.encodeResponse(0x4242, serverPub, responseMac)),
        )
        val authMac = SessionHandshake.mask(userKey, SessionHandshake.sessionAuthMac(userKey, serverPub, clientPub, 7))
        assertEquals("061009530018000771d92c0b6d8e180cc70180708e91f92e", Bytes.hex(SessionMessages.encodeAuth(7, authMac)))
    }

    @Test
    fun `gateway verifies auth from a well-behaved client`() {
        val mac = SessionHandshake.mask(userKey, SessionHandshake.sessionAuthMac(userKey, serverPub, clientPub, 7))
        SessionHandshake.verifySessionAuthMac(userKey, mac, serverPub, clientPub, 7) // must not throw
    }

    @Test
    fun `gateway rejects auth with wrong user key`() {
        val attackerKey = AesKey.of(Pbkdf2.userKey("guess"))
        val mac = SessionHandshake.mask(attackerKey, SessionHandshake.sessionAuthMac(attackerKey, serverPub, clientPub, 7))
        assertFailsWith<MacVerificationException> {
            SessionHandshake.verifySessionAuthMac(userKey, mac, serverPub, clientPub, 7)
        }
    }

    @Test
    fun `gateway rejects auth replayed to a different user id`() {
        val mac = SessionHandshake.mask(userKey, SessionHandshake.sessionAuthMac(userKey, serverPub, clientPub, 7))
        assertFailsWith<MacVerificationException> {
            SessionHandshake.verifySessionAuthMac(userKey, mac, serverPub, clientPub, 8)
        }
    }

    @Test
    fun `gateway rejects auth bound to a different key exchange`() {
        // An attacker that proxies the handshake cannot transplant the auth MAC onto its own
        // server public key: both public keys are covered by the MAC.
        val mac = SessionHandshake.mask(userKey, SessionHandshake.sessionAuthMac(userKey, serverPub, clientPub, 7))
        val otherServer = X25519.generate().publicRaw
        assertFailsWith<MacVerificationException> {
            SessionHandshake.verifySessionAuthMac(userKey, mac, otherServer, clientPub, 7)
        }
    }

    @Test
    fun `client detects a man in the middle on the device authentication`() {
        // MITM substitutes its own server public key and computes a MAC with a guessed device key.
        val mitmServerPub = X25519.generate().publicRaw
        val mitmKey = AesKey.of(Pbkdf2.deviceAuthKey("not-the-device-password"))
        val forged = SessionHandshake.mask(
            mitmKey, SessionHandshake.sessionResponseMac(mitmKey, mitmServerPub, clientPub, 0x4242),
        )
        assertFailsWith<MacVerificationException> {
            SessionHandshake.verifySessionResponseMac(deviceKey, forged, mitmServerPub, clientPub, 0x4242)
        }
    }

    @Test
    fun `client accepts a genuine session response`() {
        val mac = SessionHandshake.mask(
            deviceKey, SessionHandshake.sessionResponseMac(deviceKey, serverPub, clientPub, 0x4242),
        )
        SessionHandshake.verifySessionResponseMac(deviceKey, mac, serverPub, clientPub, 0x4242) // no throw
    }

    @Test
    fun `session request codec roundtrip`() {
        val hpai = Hpai(Hpai.IPV4_UDP, byteArrayOf(192.toByte(), 168.toByte(), 1, 10), 12345)
        val frame = SessionMessages.encodeRequest(hpai, clientPub)
        val req = SessionMessages.decodeRequest(frame)
        assertEquals(hpai, req.clientHpai)
        assertContentEquals(clientPub, req.clientPublicKey)
    }

    @Test
    fun `session response codec handles busy and full forms`() {
        val busy = SessionMessages.decodeResponse(SessionMessages.encodeBusyResponse())
        assertEquals(0, busy.sessionId)
        assertTrue(busy.isBusy)
        assertNull(busy.serverPublicKey)

        val mac = SessionHandshake.mask(
            deviceKey, SessionHandshake.sessionResponseMac(deviceKey, serverPub, clientPub, 0x4242),
        )
        val full = SessionMessages.decodeResponse(SessionMessages.encodeResponse(0x4242, serverPub, mac))
        assertEquals(0x4242, full.sessionId)
        assertContentEquals(serverPub, full.serverPublicKey)
        assertContentEquals(mac, full.mac)
    }

    @Test
    fun `session auth ignores wrong length`() {
        val bad = Bytes.unhex("06100953000a") + ByteArray(4)
        assertFailsWith<Exception> { SessionMessages.decodeAuth(bad) }
    }

    @Test
    fun `status inner packet roundtrip`() {
        for (s in SessionStatus.entries) {
            val inner = SessionMessages.encodeStatusInner(s)
            assertEquals(s, SessionMessages.decodeStatusInner(inner))
        }
        assertNull(SessionMessages.decodeStatusInner(Bytes.unhex("061004200000")))
    }

    @Test
    fun `degenerate peer key is reported as an authentication failure not a crash`() {
        assertFailsWith<KnxSecureException> { X25519.agree(clientPriv, ByteArray(32)) }
    }
}
