package io.bms.knxsecure.crypto

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * A 128-bit AES key used by KNX IP Secure (session keys, user keys, device authentication
 * codes and the backbone group key are all AES-128).
 *
 * Keys are kept in a private buffer and wiped by [close]. Java cannot guarantee that no copy
 * of the material survives (the JCE may copy it internally), so this is best-effort hygiene,
 * not a hard guarantee. Do not log [toString].
 */
class AesKey private constructor(bytes: ByteArray) : AutoCloseable {

    private val material: ByteArray = bytes.copyOf()

    init {
        require(bytes.size == KEY_BYTES) { "KNX key must be ${KEY_BYTES} bytes, got ${bytes.size}" }
    }

    internal fun secretKey(): SecretKey = SecretKeySpec(material, "AES")

    fun copyBytes(): ByteArray = material.copyOf()

    fun isDestroyed(): Boolean = material.all { it == 0.toByte() }

    override fun close() {
        material.fill(0)
    }

    override fun toString(): String = "AesKey(****)"

    companion object {
        const val KEY_BYTES = 16

        fun of(bytes: ByteArray): AesKey {
            require(bytes.size == KEY_BYTES) { "KNX key must be ${KEY_BYTES} bytes, got ${bytes.size}" }
            return AesKey(bytes)
        }

        /** Sentinel "no key" value, matching KNX device management when no device key is set. */
        fun zero(): AesKey = AesKey(ByteArray(KEY_BYTES))
    }
}
