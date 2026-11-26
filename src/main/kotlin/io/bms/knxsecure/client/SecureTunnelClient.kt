package io.bms.knxsecure.client

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxSecureException
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.Pbkdf2
import io.bms.knxsecure.crypto.ProtocolException
import io.bms.knxsecure.crypto.ReplayException
import io.bms.knxsecure.crypto.X25519
import io.bms.knxsecure.session.SequenceTracker
import io.bms.knxsecure.session.SessionHandshake
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.wire.Endpoint
import io.bms.knxsecure.wire.Hpai
import io.bms.knxsecure.wire.KnxIpHeader
import io.bms.knxsecure.wire.SecureFrameVerifier
import io.bms.knxsecure.wire.SecureFrames
import io.bms.knxsecure.wire.SessionMessages
import io.bms.knxsecure.wire.SessionStatus

/**
 * Client side of a KNX IP Secure tunnel session.
 *
 * This is not the product being delivered — the gateway is — but a *faithful* client is
 * needed both for realistic simulation and for the tests to prove the gateway's behaviour
 * from the peer's point of view. It implements the exact handshake the gateway expects, so
 * a successful run here means a real device or ETS would also succeed.
 *
 * Deliberately state-machine only (no sockets, no threads) so scenarios stay deterministic.
 */
class SecureTunnelClient(
    val endpoint: Endpoint,
    val userId: Int,
    userKeyBytes: ByteArray,
    deviceAuthKey: ByteArray?,
    val serialNumber: Long,
) {
    private val userKey = AesKey.of(userKeyBytes)
    private val deviceKey = deviceAuthKey?.let { AesKey.of(it) }

    enum class State { IDLE, REQUEST_SENT, ESTABLISHED, CLOSED }

    var state: State = State.IDLE
        private set

    var sessionId: Int = 0
        private set

    private var keys: X25519.KeyPair? = null
    private var sessionKey: AesKey? = null
    private var outbound = 0L
    private var inbound = SequenceTracker(window = 64)
    private var handshakeAttempts = 0

    val publicKey: ByteArray
        get() = keys?.publicRaw ?: throw IllegalStateException("no key pair generated yet")

    /** Builds the `0x0951` session request and records that we are waiting for a response. */
    fun buildSessionRequest(): ByteArray {
        check(state == State.IDLE || state == State.REQUEST_SENT) { "cannot start a new session in state $state" }
        if (keys == null) keys = X25519.generate()
        handshakeAttempts++
        state = State.REQUEST_SENT
        return SessionMessages.encodeRequest(
            Hpai(Hpai.IPV4_UDP, endpoint.address, endpoint.port), publicKey,
        )
    }

    /**
     * Processes the `0x0952` response: verifies the gateway's device-authentication MAC and
     * derives the session key, then produces the `0x0953` authentication message.
     *
     * @throws MacVerificationException if the gateway cannot prove possession of the device key
     */
    fun onSessionResponse(frame: ByteArray): ByteArray {
        check(state == State.REQUEST_SENT) { "unexpected session response in state $state" }
        val response = SessionMessages.decodeResponse(frame)
        if (response.isBusy) throw KnxSecureException("gateway has no free secure channels (busy)")
        val serverPub = response.serverPublicKey ?: throw ProtocolException("response has no server public key")

        if (deviceKey != null) {
            val mac = response.mac ?: throw ProtocolException("response has no MAC")
            SessionHandshake.verifySessionResponseMac(deviceKey, mac, serverPub, publicKey, response.sessionId)
        }

        val kp = keys ?: throw IllegalStateException("no key pair")
        val derived = SessionHandshake.clientAgree(kp.privateRaw, serverPub)
        sessionKey = AesKey.of(derived)
        Bytes.wipe(derived)
        sessionId = response.sessionId

        val authMac = SessionHandshake.mask(
            userKey, SessionHandshake.sessionAuthMac(userKey, serverPub, publicKey, userId),
        )
        return SessionMessages.encodeAuth(userId, authMac)
    }

    /** Processes the wrapped `0x0954` status that completes the handshake. */
    fun onStatusFrame(frame: ByteArray): SessionStatus {
        val wrapper = SecureFrameVerifier().openWrapper(sessionKey ?: throw noKey(), frame)
        check(wrapper.sessionId == sessionId) { "status for session ${wrapper.sessionId}, expected $sessionId" }
        inbound.requireAccept(wrapper.sequence, "status")
        val status = SessionMessages.decodeStatusInner(wrapper.payload)
            ?: throw ProtocolException("expected a session-status packet")
        when (status) {
            SessionStatus.AUTH_SUCCESS -> state = State.ESTABLISHED
            SessionStatus.AUTH_FAILED, SessionStatus.UNAUTHORIZED -> state = State.CLOSED
            else -> Unit
        }
        return status
    }

    fun seal(inner: ByteArray): ByteArray {
        check(state == State.ESTABLISHED) { "session is not established" }
        val frame = SecureFrames.wrap(sessionKey ?: throw noKey(), sessionId, outbound, serialNumber, 0, inner)
        outbound++
        return frame
    }

    fun buildKeepAlive(): ByteArray = seal(SessionMessages.encodeStatusInner(SessionStatus.KEEP_ALIVE))

    fun buildClose(): ByteArray = seal(SessionMessages.encodeStatusInner(SessionStatus.CLOSE))

    /** Opens an inbound wrapper (gateway -> client). */
    fun open(frame: ByteArray): ByteArray {
        check(state == State.ESTABLISHED) { "session is not established" }
        val wrapper = SecureFrameVerifier().openWrapper(sessionKey ?: throw noKey(), frame)
        check(wrapper.sessionId == sessionId) { "frame for session ${wrapper.sessionId}, expected $sessionId" }
        when (inbound.offer(wrapper.sequence)) {
            SequenceTracker.Result.DUPLICATE -> throw ReplayException("duplicate server sequence ${wrapper.sequence}")
            SequenceTracker.Result.TOO_OLD -> throw ReplayException("stale server sequence ${wrapper.sequence}")
            else -> Unit
        }
        return wrapper.payload
    }

    fun close() {
        state = State.CLOSED
        sessionKey?.close()
        keys?.let { Bytes.wipe(it.privateRaw) }
    }

    fun isEstablished(): Boolean = state == State.ESTABLISHED
    fun attempts(): Int = handshakeAttempts
    fun nextSequence(): Long = outbound

    private fun noKey() = IllegalStateException("no session key negotiated")

    companion object {
        fun withPassword(
            endpoint: Endpoint,
            userId: Int,
            password: String,
            deviceAuthPassword: String?,
            serialNumber: Long,
        ): SecureTunnelClient = SecureTunnelClient(
            endpoint = endpoint,
            userId = userId,
            userKeyBytes = Pbkdf2.userKey(password),
            deviceAuthKey = deviceAuthPassword?.let { Pbkdf2.deviceAuthKey(it) },
            serialNumber = serialNumber,
        )
    }
}

/** Wraps an arbitrary KNXnet/IP packet into a tunnel-request frame for the bus. */
object TunnelPackets {
    fun tunnelingRequest(channelId: Int, sequence: Int, payload: ByteArray): ByteArray {
        require(payload.size + 4 <= 255) { "tunnelling payload too large" }
        val body = ByteArray(4 + payload.size)
        body[0] = channelId.toByte()
        body[1] = sequence.toByte()
        body[2] = 0 // reserved
        body[3] = (payload.size + 2).toByte()
        System.arraycopy(payload, 0, body, 4, payload.size)
        return Bytes.concat(
            KnxIpHeader(io.bms.knxsecure.wire.ServiceType.TUNNELLING_REQUEST,
                KnxIpHeader.HEADER_BYTES + body.size).encode(),
            body,
        )
    }

    /** A minimal group-value write on the KNX bus: cEMI L_Data.ind would follow inside. */
    fun groupWriteCemi(groupAddress: Int, value: Byte): ByteArray {
        // cEMI: message code, add.info length, control1, control2, src, dst, npdu length, APDU
        return byteArrayOf(
            0x11, // L_Data.ind
            0x00, // additional info length
            (0x80 or 0x20).toByte(), // control 1
            0x00, // control 2
            0x11, 0x01, // source 1.1.1
            (groupAddress shr 8).toByte(), groupAddress.toByte(),
            0x01, // NPDU length
            0x00, // group value write
            value,
        )
    }
}
