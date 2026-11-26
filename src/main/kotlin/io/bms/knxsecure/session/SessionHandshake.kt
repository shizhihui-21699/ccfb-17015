package io.bms.knxsecure.session

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxCcm
import io.bms.knxsecure.crypto.KnxSecureException
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.X25519
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.wire.KnxIpHeader
import io.bms.knxsecure.wire.ServiceType

/**
 * The cryptographic core of the KNX IP Secure session handshake.
 *
 * Protocol (KNX IP Secure, session services):
 * ```
 * client                        gateway
 *   -- 0x0951 session.req  (HPAI, clientPub) ---------------------->
 *   <----------- 0x0952 session.res (sessionId, serverPub, mac_dev) --
 *   -- 0x0953 session.auth (userId, mac_user) ---------------------->
 *   <----------- 0x0950{0x0954 session.status(AUTH_SUCCESS)} --------
 * ```
 *
 * - `mac_dev` authenticates the gateway's ephemeral public key with the device
 *   authentication key, binding both public keys, so the client cannot be tricked into
 *   agreeing a key with an impostor.
 * - `mac_user` authenticates the client's user id with the user key.
 * - The session key is derived from the X25519 shared secret; no long-term key is ever sent.
 *
 * Both MACs are AES-CBC-MACs over a structure that starts with a 16-byte zero IV, then a
 * two-byte length field, then the raw message bytes followed by `serverPub XOR clientPub`.
 * Both are then counter-mode masked with the respective long-term key.
 */
object SessionHandshake {

    const val PUBLIC_KEY_BYTES = 32
    const val SESSION_KEY_BYTES = 16

    /** Derives the 128-bit session key from the raw X25519 shared secret: SHA-256, first 16 bytes. */
    fun deriveSessionKey(sharedSecret: ByteArray): ByteArray {
        require(sharedSecret.size == PUBLIC_KEY_BYTES) { "shared secret must be 32 bytes" }
        val hash = Bytes.sha256(sharedSecret)
        return hash.copyOfRange(0, SESSION_KEY_BYTES)
    }

    /**
     * Computes the *plain* (unmasked) MAC that the gateway places in the session response.
     * Masked with the device authentication key before transmission.
     */
    fun sessionResponseMac(
        deviceAuthKey: AesKey,
        serverPublicKey: ByteArray,
        clientPublicKey: ByteArray,
        sessionId: Int,
    ): ByteArray {
        val header = KnxIpHeader(
            ServiceType.SECURE_SESSION_RESPONSE,
            KnxIpHeader.HEADER_BYTES + 2 + PUBLIC_KEY_BYTES + KnxCcm.TAG_BYTES,
        ).encode()
        val msgLen = KnxIpHeader.HEADER_BYTES + 2 + PUBLIC_KEY_BYTES
        val input = Bytes.concat(
            ByteArray(16),
            byteArrayOf(0, msgLen.toByte()),
            header,
            Bytes.encodeU16(sessionId),
            Bytes.xor(serverPublicKey, 0, clientPublicKey, 0, PUBLIC_KEY_BYTES),
        )
        return KnxCcm.cbcMacZeroPad(deviceAuthKey, input)
    }

    /**
     * Computes the plain MAC for the client's session authentication message.
     * Masked with the user key before transmission.
     */
    fun sessionAuthMac(
        userKey: AesKey,
        serverPublicKey: ByteArray,
        clientPublicKey: ByteArray,
        userId: Int,
    ): ByteArray {
        val header = KnxIpHeader(
            ServiceType.SECURE_SESSION_AUTH,
            KnxIpHeader.HEADER_BYTES + 2 + KnxCcm.TAG_BYTES,
        ).encode()
        val msgLen = KnxIpHeader.HEADER_BYTES + 2 + PUBLIC_KEY_BYTES
        val input = Bytes.concat(
            ByteArray(16),
            byteArrayOf(0, msgLen.toByte()),
            header,
            Bytes.encodeU16(userId),
            Bytes.xor(serverPublicKey, 0, clientPublicKey, 0, PUBLIC_KEY_BYTES),
        )
        return KnxCcm.cbcMacZeroPad(userKey, input)
    }

    /** Verifies the device-authentication MAC of a session response (client side). */
    fun verifySessionResponseMac(
        deviceAuthKey: AesKey,
        receivedMaskedMac: ByteArray,
        serverPublicKey: ByteArray,
        clientPublicKey: ByteArray,
        sessionId: Int,
    ) {
        val received = KnxCcm.maskTag(deviceAuthKey, receivedMaskedMac)
        val expected = sessionResponseMac(deviceAuthKey, serverPublicKey, clientPublicKey, sessionId)
        if (!Bytes.constantTimeEquals(expected, received)) {
            throw MacVerificationException("session response authentication failed (device key mismatch or MITM)")
        }
    }

    /** Verifies the client's session-authentication MAC (gateway side). */
    fun verifySessionAuthMac(
        userKey: AesKey,
        receivedMaskedMac: ByteArray,
        serverPublicKey: ByteArray,
        clientPublicKey: ByteArray,
        userId: Int,
    ) {
        val received = KnxCcm.maskTag(userKey, receivedMaskedMac)
        val expected = sessionAuthMac(userKey, serverPublicKey, clientPublicKey, userId)
        if (!Bytes.constantTimeEquals(expected, received)) {
            // Do not distinguish "unknown user" from "wrong password" to an unauthenticated peer.
            throw MacVerificationException("session authentication failed")
        }
    }

    /** Mask helper reused by client and gateway code. */
    fun mask(key: AesKey, mac: ByteArray): ByteArray = KnxCcm.maskTag(key, mac)

    /**
     * Performs the client's side of the ECDH and returns (sessionKey, macForVerification).
     * Used by the simulator's fake panels so tests exercise the same code path a real device
     * would.
     */
    fun clientAgree(clientPrivate: ByteArray, serverPublic: ByteArray): ByteArray {
        val shared = X25519.agree(clientPrivate, serverPublic)
        try {
            return deriveSessionKey(shared)
        } finally {
            Bytes.wipe(shared)
        }
    }

    /** Wraps a protocol/data error into a security exception for callers that expect one. */
    internal fun fail(message: String, cause: Throwable? = null): Nothing =
        throw KnxSecureException(message, cause)
}
