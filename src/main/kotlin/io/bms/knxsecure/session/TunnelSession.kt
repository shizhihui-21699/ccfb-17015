package io.bms.knxsecure.session

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.ReplayException
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.util.MonotonicClock
import io.bms.knxsecure.wire.Endpoint
import io.bms.knxsecure.wire.KnxIpHeader
import io.bms.knxsecure.wire.SecureFrameVerifier
import io.bms.knxsecure.wire.SecureFrames
import io.bms.knxsecure.wire.SessionMessages
import io.bms.knxsecure.wire.SessionStatus
import java.util.concurrent.atomic.AtomicLong

/**
 * Lifecycle of a gateway-side secure tunnel session.
 *
 * ```
 *  PENDING  --(session.auth verifies)-->  ESTABLISHED  --(keepalive / traffic)-->  ESTABLISHED
 *     |                                        |
 *     +--(handshake timeout)--> CLOSED <-------+--(idle timeout, MAC failure, peer close, admin)
 * ```
 *
 * The session object owns:
 *  - the negotiated AES session key (wiped on close),
 *  - the inbound [SequenceTracker] (replay window),
 *  - the outbound 48-bit counter,
 *  - last-activity bookkeeping used by the idle timeout.
 *
 * It does **not** own transport. The [GatewaySessionManager] delivers datagrams in and takes
 * datagrams out, which keeps this class deterministic and thread-safe without any blocking.
 */
class TunnelSession internal constructor(
    val id: Int,
    val endpoint: Endpoint,
    internal val clientPublicKey: ByteArray,
    internal val serverKeyPair: io.bms.knxsecure.crypto.X25519.KeyPair,
    internal val sessionKey: AesKey,
    private val policy: GatewayPolicy,
    private val clock: MonotonicClock,
) {
    enum class State { PENDING, ESTABLISHED, CLOSED }

    /** Serial reported by the client in its secure wrappers (learned from the first frame). */
    @Volatile
    var clientSerialNumber: Long = -1L
        private set

    @Volatile
    var state: State = State.PENDING
        private set

    @Volatile
    var userId: Int = -1
        private set

    val createdAtMs: Long = clock.nowMs()

    @Volatile
    var lastActivityMs: Long = createdAtMs
        private set

    @Volatile
    var closeReason: CloseReason? = null
        private set

    private val inbound = SequenceTracker(window = REPLAY_WINDOW)
    private val outbound = AtomicLong(0)
    private val packetsIn = AtomicLong(0)
    private val packetsOut = AtomicLong(0)
    private val authFailures = AtomicLong(0)
    private val keepAliveSent = AtomicLong(0)

    /** Server serial number, used in every frame this gateway emits for the session. */
    @Volatile
    var serverSerialNumber: Long = 0L
        internal set

    // ---- handshake ----------------------------------------------------------------

    /**
     * Completes the handshake after the session-auth MAC has been verified.
     * Idempotent: a retransmitted auth for an already-established session is a no-op.
     */
    @Synchronized
    internal fun establish(userId: Int): Boolean {
        if (state == State.ESTABLISHED && this.userId == userId) return true
        if (state != State.PENDING) return false
        this.userId = userId
        state = State.ESTABLISHED
        lastActivityMs = clock.nowMs()
        return true
    }

    @Synchronized
    internal fun close(reason: CloseReason) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        closeReason = reason
        sessionKey.close()
        Bytes.wipe(clientPublicKey)
        Bytes.wipe(serverKeyPair.privateRaw)
    }

    fun isEstablished(): Boolean = state == State.ESTABLISHED
    fun isExpired(nowMs: Long): Boolean = when (state) {
        State.PENDING -> nowMs - createdAtMs > policy.handshakeTimeoutMs
        State.ESTABLISHED -> nowMs - lastActivityMs > policy.sessionIdleTimeoutMs
        State.CLOSED -> true
    }

    // ---- inbound ------------------------------------------------------------------

    sealed interface Inbound {
        /** A verified inner KNXnet/IP packet, ready for the bus. */
        data class Packet(val inner: ByteArray) : Inbound

        /** A keepalive status; refreshes the session but produces no work. */
        data object KeepAlive : Inbound

        /** The peer asked to close. */
        data object PeerClose : Inbound

        /** Replay or stale sequence: silently discard. */
        data class Rejected(val reason: String) : Inbound
    }

    /**
     * Verifies and decrypts an inbound secure wrapper belonging to this session.
     *
     * @throws MacVerificationException if the frame is not authentic for this session
     * @throws ReplayException if the sequence number is a replay or too old
     */
    fun openInbound(verifier: SecureFrameVerifier, frame: ByteArray): Inbound {
        checkEstablishedForTraffic()

        val wrapper = verifier.openWrapper(sessionKey, frame)

        if (wrapper.sessionId != id) {
            throw MacVerificationException("session id mismatch: got ${wrapper.sessionId}, expected $id")
        }
        if (wrapper.sequence > Bytes.SEQ_CLOSE_THRESHOLD) {
            // Peer is about to run out of sequence space; the session must be renewed.
            close(CloseReason.ADMIN)
            throw ReplayException("peer sequence ${wrapper.sequence} reached the renewal threshold")
        }

        when (inbound.offer(wrapper.sequence)) {
            SequenceTracker.Result.DUPLICATE -> throw ReplayException("duplicate sequence ${wrapper.sequence}")
            SequenceTracker.Result.TOO_OLD -> throw ReplayException("stale sequence ${wrapper.sequence}")
            SequenceTracker.Result.ACCEPTED, SequenceTracker.Result.FORWARD_ANOMALY -> Unit
        }

        clientSerialNumber = wrapper.serialNumber
        lastActivityMs = clock.nowMs()
        packetsIn.incrementAndGet()

        // The inner payload must itself be a well-formed KNXnet/IP packet.
        val innerHeader = try {
            KnxIpHeader.decode(wrapper.payload)
        } catch (e: Exception) {
            throw MacVerificationException("inner packet malformed after successful MAC: ${e.message}")
        }
        if (innerHeader.totalLength != wrapper.payload.size) {
            throw MacVerificationException("inner packet length ${innerHeader.totalLength} != payload ${wrapper.payload.size}")
        }

        return when (innerHeader.serviceType) {
            io.bms.knxsecure.wire.ServiceType.SECURE_SESSION_STATUS -> {
                when (SessionMessages.decodeStatusInner(wrapper.payload)) {
                    SessionStatus.CLOSE -> Inbound.PeerClose
                    SessionStatus.KEEP_ALIVE, SessionStatus.AUTH_SUCCESS -> Inbound.KeepAlive
                    else -> Inbound.Rejected("unexpected status")
                }
            }
            else -> Inbound.Packet(wrapper.payload)
        }
    }

    // ---- outbound -----------------------------------------------------------------

    /**
     * Wraps an inner KNXnet/IP packet for this session and advances the outbound counter.
     *
     * @throws IllegalStateException if the session is not established or the counter is
     *         exhausted (the session must be renewed before then).
     */
    @Synchronized
    fun sealOutbound(inner: ByteArray): ByteArray {
        checkEstablishedForTraffic()
        val seq = outbound.get()
        if (seq > Bytes.SEQ_CLOSE_THRESHOLD) {
            close(CloseReason.ADMIN)
            throw IllegalStateException("outbound sequence exhausted; session $id must be renewed")
        }
        val frame = SecureFrames.wrap(sessionKey, id, seq, serverSerialNumber, 0, inner)
        outbound.incrementAndGet()
        packetsOut.incrementAndGet()
        lastActivityMs = clock.nowMs()
        return frame
    }

    /** Builds a wrapped session-status frame (keepalive / auth success / close). */
    fun sealStatus(status: SessionStatus): ByteArray = sealOutbound(SessionMessages.encodeStatusInner(status))

    /** Builds a keepalive status frame; used both for liveness and to keep NAT bindings open. */
    fun sealKeepAlive(): ByteArray {
        keepAliveSent.incrementAndGet()
        return sealStatus(SessionStatus.KEEP_ALIVE)
    }

    internal fun noteAuthFailure() {
        authFailures.incrementAndGet()
    }

    fun nextOutboundSequence(): Long = outbound.get()

    fun touch() {
        lastActivityMs = clock.nowMs()
    }

    fun info(): SessionInfo = SessionInfo(
        sessionId = id,
        endpoint = endpoint,
        userId = userId,
        createdAtMs = createdAtMs,
        lastActivityMs = lastActivityMs,
        clientHighSequence = inbound.highestAccepted(),
        serverNextSequence = outbound.get(),
        packetsIn = packetsIn.get(),
        packetsOut = packetsOut.get(),
        replaysRejected = inbound.stats().rejectedReplays + inbound.stats().rejectedOld,
    )

    private fun checkEstablishedForTraffic() {
        if (state == State.CLOSED) throw IllegalStateException("session $id is closed")
        if (state != State.ESTABLISHED) throw IllegalStateException("session $id handshake is not complete")
    }

    override fun toString(): String =
        "TunnelSession(id=$id, peer=$endpoint, user=$userId, state=$state, seqOut=${outbound.get()})"

    companion object {
        /**
         * 64-entry replay window: larger than any plausible UDP reordering on a building LAN,
         * small enough that a duplicate is almost certainly a replay rather than a straggler.
         */
        const val REPLAY_WINDOW = 64
    }
}
