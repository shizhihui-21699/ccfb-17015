package io.bms.knxsecure.session

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxSecureException
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.Pbkdf2
import io.bms.knxsecure.crypto.ProtocolException
import io.bms.knxsecure.crypto.ReplayException
import io.bms.knxsecure.crypto.X25519
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.util.MonotonicClock
import io.bms.knxsecure.wire.Endpoint
import io.bms.knxsecure.wire.KnxIpHeader
import io.bms.knxsecure.wire.ProtocolFormatException
import io.bms.knxsecure.wire.SecureFrameVerifier
import io.bms.knxsecure.wire.ServiceType
import io.bms.knxsecure.wire.SessionMessages
import io.bms.knxsecure.wire.SessionStatus

/**
 * A user account: an id plus the key derived from its password.
 *
 * The plaintext password never enters the gateway. Provisioning derives the key once with
 * [Pbkdf2.userKey] and stores only the result.
 */
class UserAccount(val userId: Int, userKey: ByteArray) {
    init {
        require(userId in 0..0xffff) { "user id out of range" }
        require(userKey.size == 16) { "user key must be 16 bytes" }
    }

    internal val key: AesKey = AesKey.of(userKey)
}

/** Static configuration of the gateway's security material. */
class GatewayCredentials(
    /** Device authentication key, or null when the installation does not use one. */
    val deviceAuthKey: AesKey?,
    val users: List<UserAccount>,
    val usersById: Map<Int, UserAccount> = users.associateBy { it.userId },
)

/** What the caller should do after feeding a datagram to the manager. */
data class Handling(
    /** Datagrams to send back to the source, in order. */
    val responses: List<ByteArray> = emptyList(),
    /** Verified inner KNXnet/IP packets to forward onto the bus. */
    val busPackets: List<ByteArray> = emptyList(),
    /** Accepted without a response (keepalive, duplicate auth, ...). */
    val accepted: Boolean = true,
    /** Short reason when the datagram was dropped. */
    val droppedReason: String? = null,
) {
    companion object {
        fun drop(reason: String) = Handling(accepted = false, droppedReason = reason)
        fun accepted() = Handling()
        fun respond(vararg frames: ByteArray) = Handling(responses = frames.toList())
    }
}

/**
 * Server side of KNX IP Secure tunneling.
 *
 * Responsibilities, in the order a datagram passes through them:
 *
 *  1. **Admission** — per-source rate limiting and global load caps ([AdmissionController]).
 *     This happens before any cryptography so that a flood costs the gateway almost nothing.
 *  2. **Handshake** — session request/response/auth, with the device-authentication MAC
 *     binding the key exchange and the user-key MAC authenticating the user
 *     ([SessionHandshake]).
 *  3. **Session dispatch** — wrappers are routed by session id, then *re-checked* against the
 *     source endpoint, so an attacker cannot inject frames into someone else's session even
 *     with a valid session id.
 *  4. **Tunnel traffic** — replay-checked, decrypted, and handed to the bus callback.
 *
 * Anti-exhaustion design (the "session exhaustion attack" the brief calls out):
 *  - Pending handshakes are capped globally and per source, and expire after
 *    [GatewayPolicy.handshakeTimeoutMs]; a half-open table can never grow without bound.
 *  - Establishing a session requires *authenticating* with a user key; unauthenticated
 *    requests only ever consume the (capped, expiring) pending allowance. A pure spoofing
 *    attacker therefore cannot occupy a single tunnel slot.
 *  - PBKDF2 and X25519 work is gated by [GatewayPolicy.maxConcurrentHandshakeWork], so a
 *    handshake flood saturates a bounded number of cores but cannot stall the event loop.
 *  - When the established table is full, a new authenticated client evicts the least-recently
 *    used session that has been idle long enough, so a mass power-on does not fail behind
 *    stale entries.
 *
 * The manager performs no I/O: it returns datagrams to send. That makes it deterministic
 * under [VirtualClock] and trivially wireable to both the simulator and a real UDP socket.
 */
class GatewaySessionManager(
    private val credentials: GatewayCredentials,
    private val clock: MonotonicClock,
    private val policy: GatewayPolicy = GatewayPolicy(),
    private val serverSerialNumber: Long = 0x010203040506L,
) {
    private val verifier = SecureFrameVerifier()
    private val admission = AdmissionController(policy, clock)

    private val sessions = LinkedHashMap<Int, TunnelSession>()
    private val pending = LinkedHashMap<Endpoint, ManagedPending>()
    private var nextSessionId = 1
    private var sweptAt = 0L
    private val events = ArrayList<(GatewayEvent) -> Unit>()

    private var totalSessionsEstablished = 0L
    private var totalAuthFailures = 0L
    private var totalDropped = 0L

    init {
        require(credentials.usersById.size == credentials.users.size) { "duplicate user ids" }
    }

    // ---- public API -----------------------------------------------------------------

    fun onEvent(listener: (GatewayEvent) -> Unit) {
        events += listener
    }

    /** Feeds one received datagram. */
    @Synchronized
    fun handleDatagram(source: Endpoint, frame: ByteArray): Handling {
        sweepIfDue()
        if (!admission.admitPacket(source)) {
            totalDropped++
            return Handling.drop("rate limited")
        }
        return try {
            dispatch(source, frame)
        } catch (e: ProtocolFormatException) {
            totalDropped++
            publish(GatewayEvent.MalformedFrame(source, e.message ?: "malformed"))
            Handling.drop("malformed")
        } catch (e: ProtocolException) {
            totalDropped++
            publish(GatewayEvent.MalformedFrame(source, e.message ?: "malformed"))
            Handling.drop("malformed")
        } catch (e: MacVerificationException) {
            totalDropped++
            publish(GatewayEvent.AuthFailure(source, e.message ?: "mac failure"))
            Handling.drop("authentication failed")
        } catch (e: ReplayException) {
            publish(GatewayEvent.ReplayRejected(source, e.message ?: "replay"))
            Handling.drop("replay")
        } catch (e: KnxSecureException) {
            totalDropped++
            publish(GatewayEvent.AuthFailure(source, e.message ?: "secure failure"))
            Handling.drop("security failure")
        }
    }

    /** All established sessions, for metrics. */
    fun establishedSessions(): List<SessionInfo> =
        sessions.values.filter { it.isEstablished() }.map { it.info() }

    fun pendingHandshakes(): Int = pending.size

    fun stats(): GatewayStats = GatewayStats(
        established = sessions.values.count { it.isEstablished() },
        pendingHandshakes = pending.size,
        totalEstablished = totalSessionsEstablished,
        totalAuthFailures = totalAuthFailures,
        totalDropped = totalDropped,
        maxSessions = policy.maxSessions,
    )

    /** Sends a wrapped inner packet to a session; returns the datagram or null if unknown. */
    @Synchronized
    fun sendToSession(sessionId: Int, inner: ByteArray): ByteArray? {
        val s = sessions[sessionId] ?: return null
        if (!s.isEstablished()) return null
        return s.sealOutbound(inner)
    }

    /** Builds keepalive datagrams for every established session. Call from a scheduler. */
    @Synchronized
    fun keepAliveFrames(): List<Pair<SessionInfo, ByteArray>> =
        sessions.values.filter { it.isEstablished() }.map { it.info() to it.sealKeepAlive() }

    /** Administrative close. */
    @Synchronized
    fun closeSession(sessionId: Int, reason: CloseReason): ByteArray? {
        val s = sessions[sessionId] ?: return null
        val frame = if (s.isEstablished()) runCatching { s.sealStatus(statusFor(reason)) }.getOrNull() else null
        removeSession(s, reason)
        return frame
    }

    /** Net admission/expiry state, for tests and diagnostics. */
    fun admissionController(): AdmissionController = admission

    // ---- dispatch -------------------------------------------------------------------

    private fun dispatch(source: Endpoint, frame: ByteArray): Handling {
        val header = KnxIpHeader.decode(frame)
        return when (header.serviceType) {
            ServiceType.SECURE_SESSION_REQUEST -> onSessionRequest(source, frame)
            ServiceType.SECURE_SESSION_AUTH -> onSessionAuth(source, frame)
            ServiceType.SECURE_WRAPPER -> onSecureWrapper(source, frame)
            else -> {
                // Nothing else is accepted on the secure endpoint; do not reply (avoids being
                // used as a reflector).
                Handling.drop("unsupported service ${ServiceType.name(header.serviceType)}")
            }
        }
    }

    private fun onSessionRequest(source: Endpoint, frame: ByteArray): Handling {
        if (!admission.admitHandshake(source)) {
            totalDropped++
            publish(GatewayEvent.HandshakeRateLimited(source))
            return Handling.drop("handshake rate limited")
        }

        val request = SessionMessages.decodeRequest(frame)
        if (policy.validateHpai && !isPlausible(request.clientHpai)) {
            publish(GatewayEvent.MalformedFrame(source, "implausible HPAI"))
            return Handling.drop("invalid HPAI")
        }

        // The endpoint we answer is the HPAI the client asked us to use.
        val replyEndpoint = if (request.clientHpai.isNat) source else Endpoint.fromHpai(request.clientHpai)

        val work = admission.tryAcquireHandshakeWork() ?: run {
            totalDropped++
            publish(GatewayEvent.HandshakeOverloaded(source))
            return Handling.drop("handshake overloaded")
        }
        val pendingEntry: ManagedPending?
        try {
            pendingEntry = createPending(replyEndpoint, request.clientPublicKey)
        } catch (e: KnxSecureException) {
            publish(GatewayEvent.MalformedFrame(source, e.message ?: "invalid client key"))
            return Handling.drop("invalid client key")
        } finally {
            work.close()
        }
        if (pendingEntry == null) {
            totalDropped++
            return Handling.drop("session table unavailable")
        }

        publish(GatewayEvent.SessionRequested(source, pendingEntry.tentativeId))
        return Handling.respond(buildResponse(pendingEntry))
    }

    private fun onSessionAuth(source: Endpoint, frame: ByteArray): Handling {
        // Auth frames carry no session id, so they are matched to the pending handshake by
        // the source endpoint. A spoofed auth for someone else's pending entry simply fails
        // its MAC (it would have to know that client's view of both public keys and the user
        // key).
        val pendingEntry = pending[source]
            ?: pending.values.firstOrNull { it.endpoint.address.contentEquals(source.address) && it.endpoint.port == source.port }
            ?: return Handling.drop("no pending session for $source")

        val auth = SessionMessages.decodeAuth(frame)
        val account = credentials.usersById[auth.userId]
            ?: run {
                totalAuthFailures++
                pendingEntry.failures++
                publish(GatewayEvent.AuthFailure(source, "unknown user ${auth.userId}"))
                return finishPending(pendingEntry, SessionStatus.AUTH_FAILED)
            }

        val work = admission.tryAcquireHandshakeWork()
            ?: return Handling.drop("handshake overloaded")
        try {
            SessionHandshake.verifySessionAuthMac(
                userKey = account.key,
                receivedMaskedMac = auth.mac,
                serverPublicKey = pendingEntry.serverPublicKey,
                clientPublicKey = pendingEntry.clientPublicKey,
                userId = auth.userId,
            )
        } catch (e: MacVerificationException) {
            totalAuthFailures++
            pendingEntry.failures++
            publish(GatewayEvent.AuthFailure(source, e.message ?: "auth mac"))
            return finishPending(pendingEntry, SessionStatus.AUTH_FAILED)
        } finally {
            work.close()
        }

        // Authenticated: promote the pending handshake to a real session.
        val session = promote(pendingEntry, source, auth.userId)
            ?: return finishPending(pendingEntry, SessionStatus.UNAUTHORIZED)
        totalSessionsEstablished++
        publish(GatewayEvent.SessionEstablished(session.info()))
        return Handling.respond(session.sealStatus(SessionStatus.AUTH_SUCCESS))
    }

    private fun onSecureWrapper(source: Endpoint, frame: ByteArray): Handling {
        // Cheap pre-filter: find the session by its session id, then require the source
        // endpoint to match. This stops cross-session injection without leaking whether an
        // id exists (both cases return the same silent drop).
        val sessionId = runCatching {
            Bytes.u16(frame, KnxIpHeader.HEADER_BYTES)
        }.getOrNull() ?: return Handling.drop("short wrapper")

        val session = sessions[sessionId] ?: return Handling.drop("unknown session")
        if (session.endpoint != source) {
            publish(GatewayEvent.AuthFailure(source, "session $sessionId used from unexpected endpoint"))
            return Handling.drop("endpoint mismatch")
        }
        if (!session.isEstablished()) return Handling.drop("handshake incomplete")

        return when (val inbound = session.openInbound(verifier, frame)) {
            is TunnelSession.Inbound.Packet -> Handling(busPackets = listOf(inbound.inner))
            TunnelSession.Inbound.KeepAlive -> Handling.accepted()
            TunnelSession.Inbound.PeerClose -> {
                removeSession(session, CloseReason.PEER_DISCONNECT)
                Handling.accepted()
            }
            is TunnelSession.Inbound.Rejected -> Handling.drop(inbound.reason)
        }
    }

    private class ManagedPending(
        val tentativeId: Int,
        val endpoint: Endpoint,
        val clientPublicKey: ByteArray,
        val serverKeyPair: X25519.KeyPair,
        val sessionKeyBytes: ByteArray,
        val startedAtMs: Long,
    ) {
        var failures: Int = 0
        val serverPublicKey: ByteArray get() = serverKeyPair.publicRaw
        fun expired(now: Long, timeout: Long): Boolean = now - startedAtMs > timeout
    }

    private fun createPending(endpoint: Endpoint, clientPublicKey: ByteArray): ManagedPending? {
        // Replacing an existing pending entry for the same endpoint is normal (retransmission).
        pending.remove(endpoint)

        if (pending.size >= policy.maxPendingHandshakes) {
            // A flood must not lock legitimate clients out of the pending table. Evict the
            // oldest half-open entry: it is, by construction, unauthenticated and therefore
            // has no claim on the resource. (A legitimate client simply retransmits.)
            val victim = pending.entries.minByOrNull { it.value.startedAtMs }
            if (victim != null) {
                pending.remove(victim.key)
                Bytes.wipe(victim.value.sessionKeyBytes)
                Bytes.wipe(victim.value.serverKeyPair.privateRaw)
                publish(GatewayEvent.HandshakeExpired(victim.key))
            } else {
                publish(GatewayEvent.PendingTableFull(endpoint))
                return null
            }
        }
        val perSource = pending.values.count { it.endpoint == endpoint }
        if (perSource >= policy.maxPendingPerSource) return null

        val serverKeyPair = X25519.generate()
        val shared = try {
            X25519.agree(serverKeyPair.privateRaw, clientPublicKey)
        } catch (e: KnxSecureException) {
            // Malformed / small-order client key: treat as an invalid request, not a crash.
            Bytes.wipe(serverKeyPair.privateRaw)
            throw e
        }
        val sessionKeyBytes = try {
            SessionHandshake.deriveSessionKey(shared)
        } finally {
            Bytes.wipe(shared)
        }
        val id = allocateSessionId()
        val p = ManagedPending(id, endpoint, clientPublicKey, serverKeyPair, sessionKeyBytes, clock.nowMs())
        pending[endpoint] = p
        return p
    }

    private fun buildResponse(p: ManagedPending): ByteArray {
        val deviceKey = credentials.deviceAuthKey
        return if (deviceKey == null) {
            // No device authentication configured: send the public key with a zero MAC. The
            // client-side of this project always verifies; third-party tooling may not.
            SessionMessages.encodeResponse(p.tentativeId, p.serverPublicKey, ByteArray(16))
        } else {
            val mac = SessionHandshake.sessionResponseMac(deviceKey, p.serverPublicKey, p.clientPublicKey, p.tentativeId)
            SessionMessages.encodeResponse(p.tentativeId, p.serverPublicKey, SessionHandshake.mask(deviceKey, mac))
        }
    }

    private fun promote(p: ManagedPending, source: Endpoint, userId: Int): TunnelSession? {
        pending.remove(p.endpoint)
        // Make room in the established table.
        if (sessions.values.count { it.isEstablished() } >= policy.maxSessions) {
            if (!evictOne(clock.nowMs())) {
                return null
            }
        }
        val session = TunnelSession(
            id = p.tentativeId,
            endpoint = p.endpoint,
            clientPublicKey = p.clientPublicKey,
            serverKeyPair = p.serverKeyPair,
            sessionKey = AesKey.of(p.sessionKeyBytes),
            policy = policy,
            clock = clock,
        )
        session.serverSerialNumber = serverSerialNumber
        Bytes.wipe(p.sessionKeyBytes)
        if (!session.establish(userId)) return null
        sessions[p.tentativeId] = session
        return session
    }

    private fun finishPending(p: ManagedPending, status: SessionStatus): Handling {
        // Do not discard the pending entry on the first failure: a legitimate client may have
        // mistyped a password once. Discard after a few attempts or on timeout.
        if (status == SessionStatus.AUTH_FAILED && p.failures < MAX_AUTH_ATTEMPTS) {
            return Handling.accepted()
        }
        pending.remove(p.endpoint)
        Bytes.wipe(p.sessionKeyBytes)
        Bytes.wipe(p.serverKeyPair.privateRaw)
        val frame = buildStatusFrame(p, status)
        return if (frame != null) Handling.respond(frame) else Handling.accepted()
    }

    private fun buildStatusFrame(p: ManagedPending, status: SessionStatus): ByteArray? {
        // Status is wrapped with the not-yet-confirmed session key; a client that cannot
        // decrypt it will simply time out, which is the correct behaviour.
        return runCatching {
            io.bms.knxsecure.wire.SecureFrames.wrap(
                AesKey.of(p.sessionKeyBytes), p.tentativeId, 0, serverSerialNumber, 0,
                SessionMessages.encodeStatusInner(status),
            )
        }.getOrNull()
    }

    // ---- lifecycle ------------------------------------------------------------------

    private fun sweepIfDue() {
        val now = clock.nowMs()
        if (now - sweptAt < policy.sweepIntervalMs) return
        sweptAt = now

        val expiredPending = pending.values.filter { it.expired(now, policy.handshakeTimeoutMs) }
        for (p in expiredPending) {
            pending.remove(p.endpoint)
            Bytes.wipe(p.sessionKeyBytes)
            Bytes.wipe(p.serverKeyPair.privateRaw)
            publish(GatewayEvent.HandshakeExpired(p.endpoint))
        }

        val expiredSessions = sessions.values.filter { it.isEstablished() && it.isExpired(now) }
        for (s in expiredSessions) {
            removeSession(s, CloseReason.IDLE_TIMEOUT)
            publish(GatewayEvent.SessionExpired(s.id, s.endpoint))
        }
    }

    private fun evictOne(now: Long): Boolean {
        if (!policy.evictIdleWhenFull) return false
        val victim = sessions.values
            .filter { it.isEstablished() && now - it.lastActivityMs >= policy.minEvictableIdleMs }
            .minByOrNull { it.lastActivityMs }
            ?: return false
        removeSession(victim, CloseReason.ADMIN)
        publish(GatewayEvent.SessionEvicted(victim.id, victim.endpoint))
        return true
    }

    private fun removeSession(s: TunnelSession, reason: CloseReason) {
        sessions.remove(s.id)
        s.close(reason)
    }

    private fun allocateSessionId(): Int {
        if (sessions.size + pending.size >= policy.maxSessions + policy.maxPendingHandshakes) {
            // Caller checks separately; this is just a safety valve.
        }
        repeat(0xffff) {
            val id = nextSessionId
            nextSessionId = if (nextSessionId >= 0xffff) 1 else nextSessionId + 1
            if (id != 0 && !sessions.containsKey(id) && pending.values.none { it.tentativeId == id }) return id
        }
        throw IllegalStateException("no free session id")
    }

    private fun isPlausible(hpai: io.bms.knxsecure.wire.Hpai): Boolean {
        if (hpai.isNat) return true
        // A real client supplies a routable-looking endpoint. All-zero address with a non-zero
        // port, or a port of 0 with a real address, is a malformed request.
        val zeroAddr = hpai.address.all { it == 0.toByte() }
        return !(zeroAddr && hpai.port != 0) && hpai.port != 0
    }

    private fun publish(event: GatewayEvent) {
        for (l in events) runCatching { l(event) }
    }

    companion object {
        private const val MAX_AUTH_ATTEMPTS = 3

        private fun statusFor(reason: CloseReason): SessionStatus = when (reason) {
            CloseReason.NORMAL, CloseReason.PEER_DISCONNECT, CloseReason.ADMIN -> SessionStatus.CLOSE
            CloseReason.AUTH_FAILED -> SessionStatus.AUTH_FAILED
            CloseReason.UNAUTHORIZED -> SessionStatus.UNAUTHORIZED
            CloseReason.IDLE_TIMEOUT -> SessionStatus.TIMEOUT
        }
    }
}

/** Machine-readable gateway events for monitoring and the simulation harness. */
sealed interface GatewayEvent {
    data class SessionRequested(val source: Endpoint, val tentativeId: Int) : GatewayEvent
    data class SessionEstablished(val info: SessionInfo) : GatewayEvent
    data class SessionExpired(val sessionId: Int, val endpoint: Endpoint) : GatewayEvent
    data class SessionEvicted(val sessionId: Int, val endpoint: Endpoint) : GatewayEvent
    data class HandshakeRateLimited(val source: Endpoint) : GatewayEvent
    data class HandshakeOverloaded(val source: Endpoint) : GatewayEvent
    data class HandshakeExpired(val endpoint: Endpoint) : GatewayEvent
    data class PendingTableFull(val source: Endpoint) : GatewayEvent
    data class AuthFailure(val source: Endpoint, val reason: String) : GatewayEvent
    data class ReplayRejected(val source: Endpoint, val reason: String) : GatewayEvent
    data class MalformedFrame(val source: Endpoint, val reason: String) : GatewayEvent
}

data class GatewayStats(
    val established: Int,
    val pendingHandshakes: Int,
    val totalEstablished: Long,
    val totalAuthFailures: Long,
    val totalDropped: Long,
    val maxSessions: Int,
)
