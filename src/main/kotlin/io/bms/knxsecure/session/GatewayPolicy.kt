package io.bms.knxsecure.session

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.util.MonotonicClock
import io.bms.knxsecure.wire.Endpoint
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tunables and hard limits for the gateway's secure session layer.
 *
 * The numbers are chosen around the two normal-world scenarios the deployment must survive:
 *
 *  - **Mass power-on.** A floor of panels energises together; a few hundred devices may open
 *    tunnels within a second or two. The pending-table allowance and the per-source cap must
 *    be far above that, and the handshake work per request must stay tiny.
 *  - **Night / energy-saving mode.** Tunnels may be idle for long periods and clients stretch
 *    their keep-alive interval. The idle timeout must tolerate long gaps, and expiry must never
 *    be the *first* thing a returning client experiences.
 */
data class GatewayPolicy(
    /** Maximum number of simultaneously established tunnel sessions. */
    val maxSessions: Int = 256,
    /** Maximum number of half-open handshakes (session request seen, auth not yet done). */
    val maxPendingHandshakes: Int = 512,
    /**
     * Maximum pending handshakes from one source address. A NAT'd building-management server
     * may legitimately multiplex many clients, so this is generous; a spoofed-source flood is
     * spread over many addresses anyway, which the global cap plus cost bounding handles.
     */
    val maxPendingPerSource: Int = 64,
    /** Lifetime of a pending handshake; KNX clients complete it in well under a second. */
    val handshakeTimeoutMs: Long = 10_000,
    /**
     * Idle timeout for established sessions. Defaults to 20 minutes, long enough for nightly
     * heartbeat intervals measured in minutes; refresh it on any authenticated traffic.
     */
    val sessionIdleTimeoutMs: Long = 20 * 60_000,
    /** Client keep-alive interval we advertise / expect (informational for the gateway). */
    val keepAliveIntervalMs: Long = 60_000,
    /** How often expired sessions and pending handshakes are swept. */
    val sweepIntervalMs: Long = 1_000,
    /** Per-source admission budget for handshake attempts, refilled per second. */
    val handshakeRatePerSecond: Double = 20.0,
    /** Burst allowance for the per-source handshake budget. */
    val handshakeBurst: Double = 40.0,
    /** Per-source admission budget for packets of any kind, refilled per second. */
    val packetRatePerSecond: Double = 500.0,
    /** Burst allowance for the per-source packet budget. */
    val packetBurst: Double = 1000.0,
    /** Maximum simultaneous handshakes being computed (bounds PBKDF2 CPU). */
    val maxConcurrentHandshakeWork: Int = 8,
    /** Reject session requests whose HPAI is implausible (zero port with a non-zero address). */
    val validateHpai: Boolean = true,
    /**
     * When the session table is full, evict the least-recently-used *idle* session instead of
     * refusing the new client. Protects a mass power-on from starving behind stale entries.
     */
    val evictIdleWhenFull: Boolean = true,
    /** An entry is only evictable if idle for at least this long (prevents thrashing). */
    val minEvictableIdleMs: Long = 30_000,
) {
    init {
        require(maxSessions > 0)
        require(maxPendingHandshakes > 0)
        require(maxPendingPerSource > 0)
        require(handshakeTimeoutMs > 0)
        require(sessionIdleTimeoutMs > handshakeTimeoutMs) { "idle timeout must exceed the handshake timeout" }
        require(sweepIntervalMs > 0)
        require(handshakeRatePerSecond > 0)
        require(packetRatePerSecond > 0)
        require(maxConcurrentHandshakeWork > 0)
        require(minEvictableIdleMs >= 0)
    }
}

/** Why a session closed; surfaced as a `0x0954` status where the peer is still reachable. */
enum class CloseReason(val statusCode: Int) {
    NORMAL(0),
    AUTH_FAILED(1),
    UNAUTHORIZED(2),
    IDLE_TIMEOUT(3),
    PEER_DISCONNECT(5),
    ADMIN(5),
}

/** Immutable view of one established session, safe to hand to metrics/logging. */
data class SessionInfo(
    val sessionId: Int,
    val endpoint: Endpoint,
    val userId: Int,
    val createdAtMs: Long,
    val lastActivityMs: Long,
    /** Highest sequence number accepted from the client. */
    val clientHighSequence: Long,
    /** Next sequence number the gateway will use. */
    val serverNextSequence: Long,
    val packetsIn: Long,
    val packetsOut: Long,
    val replaysRejected: Long,
) {
    fun describe(): String =
        "session=$sessionId user=$userId peer=$endpoint in=$packetsIn out=$packetsOut " +
            "replays=$replaysRejected seq=${clientHighSequence}"
}

/**
 * Tracks admission and load. Kept separate from the session table so that the policy is
 * testable on its own and the table stays about identity, not about rate limits.
 */
class AdmissionController(
    private val policy: GatewayPolicy,
    private val clock: MonotonicClock,
) {
    private class Bucket(var tokens: Double, var lastRefillMs: Long)

    private val handshakeBuckets = HashMap<Endpoint, Bucket>()
    private val packetBuckets = HashMap<Endpoint, Bucket>()
    private val inFlightHandshakeWork = AtomicInteger(0)
    private var lastSweepMs = 0L

    /** Returns true if a handshake from [endpoint] is admitted. */
    @Synchronized
    fun admitHandshake(endpoint: Endpoint): Boolean {
        val now = clock.nowMs()
        sweepIdleBuckets(now)
        val b = handshakeBuckets.getOrPut(endpoint) { Bucket(policy.handshakeBurst, now) }
        refill(b, now, policy.handshakeRatePerSecond, policy.handshakeBurst)
        if (b.tokens < 1.0) return false
        b.tokens -= 1.0
        return true
    }

    /** Returns true if a packet from [endpoint] is admitted. */
    @Synchronized
    fun admitPacket(endpoint: Endpoint): Boolean {
        val now = clock.nowMs()
        val b = packetBuckets.getOrPut(endpoint) { Bucket(policy.packetBurst, now) }
        refill(b, now, policy.packetRatePerSecond, policy.packetBurst)
        if (b.tokens < 1.0) return false
        b.tokens -= 1.0
        return true
    }

    /**
     * Acquires a slot for expensive handshake computation (PBKDF2 + X25519). Returns null if
     * the gateway is already at its concurrency limit, so a flood cannot pin every core.
     */
    fun tryAcquireHandshakeWork(): AutoCloseable? {
        if (inFlightHandshakeWork.incrementAndGet() > policy.maxConcurrentHandshakeWork) {
            inFlightHandshakeWork.decrementAndGet()
            return null
        }
        return AutoCloseable { inFlightHandshakeWork.decrementAndGet() }
    }

    fun inFlightHandshakeWork(): Int = inFlightHandshakeWork.get()

    @Synchronized
    fun trackedSources(): Int = handshakeBuckets.size.coerceAtLeast(packetBuckets.size)

    private fun sweepIdleBuckets(now: Long) {
        if (now - lastSweepMs < policy.sweepIntervalMs) return
        lastSweepMs = now
        val stale = now - 60_000
        handshakeBuckets.entries.removeIf { it.value.lastRefillMs < stale }
        packetBuckets.entries.removeIf { it.value.lastRefillMs < stale }
    }

    private fun refill(b: Bucket, now: Long, ratePerSecond: Double, capacity: Double) {
        val elapsed = (now - b.lastRefillMs).coerceAtLeast(0)
        if (elapsed > 0) {
            b.lastRefillMs = now
            b.tokens = minOf(capacity, b.tokens + ratePerSecond * (elapsed / 1000.0))
        }
    }
}
