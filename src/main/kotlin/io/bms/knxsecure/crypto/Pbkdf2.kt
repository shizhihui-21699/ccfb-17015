package io.bms.knxsecure.crypto

import java.nio.charset.StandardCharsets
import java.util.Arrays
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Password derivation for KNX IP Secure.
 *
 * Two independent key hierarchies exist:
 *
 *  - **User password** -> *user key*: authenticates a client user id during the session
 *    authentication phase (`0x0953`).
 *  - **Device authentication code** -> *device authentication key*: authenticates the
 *    gateway's public key in the session response (`0x0952`) so a client cannot be
 *    man-in-the-middled during the X25519 exchange.
 *
 * Both use PBKDF2-HMAC-SHA256 with 65 536 iterations and a 128-bit output, matching the KNX
 * IP Secure specification. The salts are fixed constants, not per-device random values; the
 * password therefore *is* the long-term secret and must be chosen with enough entropy.
 * That is why callers must rate-limit and back off failed authentications.
 */
object Pbkdf2 {

    const val ITERATIONS = 65_536
    const val KEY_BYTES = 16

    private val USER_SALT = "user-password.1.secure.ip.knx.org".toByteArray(StandardCharsets.US_ASCII)
    private val DEVICE_SALT =
        "device-authentication-code.1.secure.ip.knx.org".toByteArray(StandardCharsets.US_ASCII)

    /**
     * Derives the 16-byte user key from a user password.
     *
     * Non-printable characters are replaced by `'?'` exactly as the specification requires,
     * so that passwords typed on devices with different keyboards map to the same key.
     *
     * @param wipe if true (default) the supplied array is zeroed before returning
     */
    fun userKey(password: CharArray, wipe: Boolean = true): ByteArray = derive(password, USER_SALT, wipe)

    /**
     * Derives the 16-byte device authentication key from a device authentication password.
     *
     * @param wipe if true (default) the supplied array is zeroed before returning
     */
    fun deviceAuthKey(password: CharArray, wipe: Boolean = true): ByteArray = derive(password, DEVICE_SALT, wipe)

    /** Convenience overload for tests and configuration files. */
    fun userKey(password: String): ByteArray = userKey(password.toCharArray(), wipe = true)

    fun deviceAuthKey(password: String): ByteArray = deviceAuthKey(password.toCharArray(), wipe = true)

    private fun derive(password: CharArray, salt: ByteArray, wipe: Boolean): ByteArray {
        // Sanitise in place on a copy so the caller's array is only ever wiped, never mutated
        // to a different value silently.
        val sanitised = CharArray(password.size) { i ->
            val c = password[i]
            if (c.code < 0x20 || c.code > 0x7e) '?' else c
        }
        val spec = PBEKeySpec(sanitised, salt, ITERATIONS, KEY_BYTES * 8)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val key = factory.generateSecret(spec).encoded
            require(key.size == KEY_BYTES) { "unexpected PBKDF2 output length ${key.size}" }
            return key
        } finally {
            spec.clearPassword()
            Arrays.fill(sanitised, '\u0000')
            if (wipe) Arrays.fill(password, '\u0000')
        }
    }
}
