package io.bms.knxsecure.crypto

import io.bms.knxsecure.util.Bytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Primitive-level known-answer tests.
 *
 * The PBKDF2 and X25519 vectors come from the standards; the KNX wrapper vectors were
 * produced by the reference KNX IP Secure implementation (calimero-core 3.0-M1) so that this
 * gateway is wire-compatible with third-party devices and ETS.
 */
class CryptoVectorsTest {

    // ---- X25519 (RFC 7748 section 6.1) ------------------------------------------------

    @Test
    fun `X25519 RFC 7748 raw scalar to public key`() {
        val aPriv = Bytes.unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val aPub = Bytes.unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        assertContentEquals(aPub, X25519.publicFromPrivate(aPriv))

        val bPriv = Bytes.unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bPub = Bytes.unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        assertContentEquals(bPub, X25519.publicFromPrivate(bPriv))
    }

    @Test
    fun `X25519 RFC 7748 shared secret`() {
        val aPriv = Bytes.unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bPriv = Bytes.unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bPub = Bytes.unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val aPub = Bytes.unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val expected = Bytes.unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        assertContentEquals(expected, X25519.agree(aPriv, bPub))
        assertContentEquals(expected, X25519.agree(bPriv, aPub))
    }

    @Test
    fun `X25519 rejects small order public keys`() {
        val priv = Bytes.unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        // All-zero and u=1 points have small order; the JDK raises and we normalise that to
        // an authentication failure instead of a crash.
        assertFailsWith<KnxSecureException> { X25519.agree(priv, ByteArray(32)) }
        assertFailsWith<KnxSecureException> {
            X25519.agree(priv, ByteArray(32).also { it[0] = 1 })
        }
    }

    @Test
    fun `X25519 generated key pairs agree`() {
        val a = X25519.generate()
        val b = X25519.generate()
        assertContentEquals(X25519.agree(a.privateRaw, b.publicRaw), X25519.agree(b.privateRaw, a.publicRaw))
    }

    // ---- PBKDF2 -----------------------------------------------------------------------

    @Test
    fun `KNX user password derivation`() {
        // 65536 iterations, salt "user-password.1.secure.ip.knx.org", 128-bit output.
        assertEquals("14ddf711084a0d1e6e2cf97e8fbf70f9", Bytes.hex(Pbkdf2.userKey("password")))
        assertEquals("441b490b88af08d228372525b6afb04a", Bytes.hex(Pbkdf2.userKey("topsecret")))
    }

    @Test
    fun `KNX device authentication code derivation`() {
        assertEquals("b30418583a16f600aad708f0d6822bc6", Bytes.hex(Pbkdf2.deviceAuthKey("device-pw")))
    }

    @Test
    fun `non-ASCII characters are mapped to question mark`() {
        // 'ä' and 'ö' must map to '?', so this equals hashing "p?ssw?rd".
        assertEquals(Bytes.hex(Pbkdf2.userKey("p?ssw?rd")), Bytes.hex(Pbkdf2.userKey("pässwörd")))
        assertEquals("1eb8077e7312a4c673896c5affb87136", Bytes.hex(Pbkdf2.userKey("pässwörd")))
    }

    @Test
    fun `password char array is wiped`() {
        val pw = "secret".toCharArray()
        Pbkdf2.userKey(pw)
        assertTrue(pw.all { it == '\u0000' })
    }

    // ---- KNX CBC-MAC / CCM known answers ----------------------------------------------

    @Test
    fun `CBC-MAC matches RFC 4493 AES-CMAC example 2 over a single zero padded block`() {
        // RFC 4493 example 2 has no padding, but a zero-padded MAC of the same 16-byte input
        // is a useful sanity check of the primitives (single block, zero IV).
        val key = AesKey.of(Bytes.unhex("2b7e151628aed2a6abf7158809cf4f3c"))
        val mac = KnxCcm.cbcMacZeroPad(key, Bytes.unhex("6bc1bee22e409f96e93d7e117393172a"))
        // one-block CBC-MAC = AES(key, block)
        assertContentEquals(Bytes.unhex("3ad77bb40d7a3660a89ecaf32466ef97"), mac)
    }

    @Test
    fun `session response MAC matches reference implementation`() {
        val devKey = AesKey.of(Bytes.unhex("b30418583a16f600aad708f0d6822bc6"))
        val clientPub = Bytes.unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val serverPub = Bytes.unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val xor = Bytes.xor(serverPub, 0, clientPub, 0, 32)
        val header = Bytes.unhex("061009520038")
        val macInput = Bytes.concat(ByteArray(16), byteArrayOf(0, 40), header, Bytes.encodeU16(0x4242), xor)
        val mac = KnxCcm.cbcMacZeroPad(devKey, macInput)
        assertEquals("6ab3632a2c311cd3992f6f16e4704678", Bytes.hex(mac))
        assertEquals("262d7d328b77e2946f21c361c327c104", Bytes.hex(KnxCcm.maskTag(devKey, mac)))
    }

    @Test
    fun `security info block layout`() {
        val si = KnxCcm.securityInfo(0x02468ace1357L, 0x001122334455L, 0xbeef, 0x0029)
        assertEquals("02468ace1357001122334455beef0029", Bytes.hex(si))
    }

    @Test
    fun `KTX mask is an involution and refuses oversized frames`() {
        val key = AesKey.of(Bytes.unhex("000102030405060708090a0b0c0d0e0f"))
        val si = KnxCcm.securityInfo(1, 2, 3, 0xff00)
        val data = ByteArray(50) { it.toByte() }
        val once = KnxCcm.mask(key, data, si)
        assertContentEquals(data, KnxCcm.mask(key, once, si))
        assertFailsWith<IllegalArgumentException> { KnxCcm.mask(key, ByteArray(4100), si) }
    }
}
