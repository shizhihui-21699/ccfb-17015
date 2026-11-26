package io.bms.knxsecure.crypto

import io.bms.knxsecure.util.Bytes
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * X25519 Diffie-Hellman as used during the KNX IP Secure session request phase.
 *
 * Wire encoding is the RFC 7748 little-endian 32-byte encoding. The JDK's `XECPublicKeySpec`
 * takes a BigInteger holding the same u-coordinate in big-endian, so every wire value is
 * reversed on the way in and out. This was verified against RFC 7748 section 6.1 and against
 * the reference KNX implementation.
 */
object X25519 {

    const val RAW_KEY_BYTES = 32

    class KeyPair(val privateRaw: ByteArray, val publicRaw: ByteArray) {
        override fun toString(): String = "X25519.KeyPair(pub=${Bytes.hex(publicRaw)})"
    }

    /**
     * Generates a fresh ephemeral key pair. The private scalar is returned in RFC 7748
     * little-endian form (the form the JDK produces and consumes).
     */
    fun generate(): KeyPair {
        val kp = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        val priv = (kp.private as XECPrivateKey).scalar.orElseThrow {
            IllegalStateException("JDK did not expose the X25519 private scalar")
        }
        return KeyPair(priv.copyOf(), encodePublic(kp.public as XECPublicKey))
    }

    /**
     * Derives the public key for a given raw private scalar without generating a new key pair.
     * Used by the test-suite for RFC 7748 vectors and by deterministic simulations.
     */
    fun publicFromPrivate(privateRaw: ByteArray): ByteArray {
        require(privateRaw.size == RAW_KEY_BYTES) { "raw X25519 private key must be 32 bytes" }
        val privateKey = privateKey(privateRaw)
        val base = publicKey(ByteArray(RAW_KEY_BYTES).also { it[0] = 9 })
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privateKey)
        ka.doPhase(base, true)
        return ka.generateSecret()
    }

    /**
     * Computes the shared secret.
     *
     * @return 32-byte RFC 7748 little-endian shared secret
     * @throws KnxSecureException on a malformed, non-canonical or small-order public key, or
     *         if the resulting secret is the all-zero value
     */
    fun agree(privateRaw: ByteArray, peerPublicRaw: ByteArray): ByteArray {
        require(privateRaw.size == RAW_KEY_BYTES) { "raw X25519 private key must be 32 bytes" }
        require(peerPublicRaw.size == RAW_KEY_BYTES) { "peer X25519 public key must be 32 bytes" }
        try {
            val ka = KeyAgreement.getInstance("X25519")
            ka.init(privateKey(privateRaw))
            ka.doPhase(publicKey(peerPublicRaw), true)
            val secret = ka.generateSecret()
            if (secret.size != RAW_KEY_BYTES || Bytes.isAllZero(secret)) {
                Bytes.wipe(secret)
                throw KnxSecureException("X25519 produced a degenerate shared secret (small-order public key)")
            }
            return secret
        } catch (e: KnxSecureException) {
            throw e
        } catch (e: GeneralSecurityException) {
            throw KnxSecureException("X25519 key agreement failed: ${e.message}", e)
        } catch (e: IllegalArgumentException) {
            // BigInteger / key spec rejects: treat as an authentication failure, not a crash.
            throw KnxSecureException("invalid peer X25519 public key", e)
        }
    }

    /** Wire public key -> JDK public key. Masks the unused top bit per RFC 7748. */
    private fun publicKey(wire: ByteArray): PublicKey {
        val be = Bytes.reversed(wire)          // LE -> BE
        be[0] = (be[0].toInt() and 0x7f).toByte() // RFC 7748 decodeUCoordinate: clear bit 255
        val u = BigInteger(1, be)
        return KeyFactory.getInstance("X25519")
            .generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, u))
    }

    private fun privateKey(raw: ByteArray): PrivateKey =
        KeyFactory.getInstance("X25519")
            .generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, raw.copyOf()))

    /** JDK public key -> RFC 7748 little-endian wire encoding. */
    private fun encodePublic(key: XECPublicKey): ByteArray {
        val be = Bytes.padLeft(unsignedMagnitude(key.u), RAW_KEY_BYTES)
        return Bytes.reversed(be)
    }

    /** BigInteger.toByteArray() can carry a leading 0x00 sign byte; strip it. */
    private fun unsignedMagnitude(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        if (b.size > RAW_KEY_BYTES && b[0] == 0.toByte()) return b.copyOfRange(1, b.size)
        return b
    }
}
