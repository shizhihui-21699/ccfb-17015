package io.bms.knxsecure

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.multicast.SecureRoutingReceiver
import io.bms.knxsecure.multicast.TimeSyncGuard
import io.bms.knxsecure.session.GatewayCredentials
import io.bms.knxsecure.session.GatewayEvent
import io.bms.knxsecure.session.GatewayPolicy
import io.bms.knxsecure.session.GatewaySessionManager
import io.bms.knxsecure.session.Handling
import io.bms.knxsecure.session.TunnelSession
import io.bms.knxsecure.util.MonotonicClock
import io.bms.knxsecure.wire.Endpoint

/**
 * The secure tunnel gateway: one object that owns both the unicast (tunnel) and multicast
 * (routing) halves of KNX IP Secure.
 *
 * ```
 *   panels / ETS  ── unicast ──▶  GatewaySessionManager  ──┐
 *                                                          ├─▶ bus (inner KNXnet/IP packets)
 *   backbone      ── multicast ─▶  SecureRoutingReceiver  ──┘
 * ```
 *
 * The gateway never blocks and has no threads. Callers feed it datagrams and send the
 * frames it returns, which makes it embeddable in both a Netty/NIO pipeline and the
 * deterministic simulator. All timing flows through [MonotonicClock] so the whole thing can
 * run on [io.bms.knxsecure.util.VirtualClock] for tests.
 */
class SecureGateway(
    credentials: GatewayCredentials,
    private val clock: MonotonicClock,
    policy: GatewayPolicy = GatewayPolicy(),
    val serialNumber: Long = 0x010203040506L,
    groupKey: AesKey? = null,
    timeSyncConfig: TimeSyncGuard.Config = TimeSyncGuard.Config(),
    routingConfig: SecureRoutingReceiver.Config = SecureRoutingReceiver.Config(),
) : AutoCloseable {

    private val sessions = GatewaySessionManager(credentials, clock, policy, serialNumber)

    /** Non-null only if a backbone group key was configured (routing mode enabled). */
    val routing: SecureRoutingReceiver? = groupKey?.let {
        val guard = TimeSyncGuard(clock, timeSyncConfig)
        SecureRoutingReceiver(it, clock, guard, serialNumber, routingConfig)
    }

    private val eventListeners = ArrayList<(GatewayEvent) -> Unit>()
    private var closed = false

    init {
        sessions.onEvent { e -> eventListeners.forEach { runCatching { it(e) } } }
    }

    fun onEvent(listener: (GatewayEvent) -> Unit) {
        eventListeners += listener
    }

    /** Registers a listener for multicast-clock security alarms. */
    fun onTimeAlarm(listener: (TimeSyncGuard.Alarm, String) -> Unit) {
        routing?.timeGuard()?.onAlarm(listener)
    }

    /**
     * Processes a unicast datagram addressed to the gateway (session handshake or tunnel traffic).
     */
    @Synchronized
    fun onUnicast(source: Endpoint, frame: ByteArray): Handling {
        checkOpen()
        return sessions.handleDatagram(source, frame)
    }

    /** Processes a multicast datagram from the backbone (secure routing / group-sync). */
    @Synchronized
    fun onMulticast(frame: ByteArray): SecureRoutingReceiver.Outcome {
        checkOpen()
        val r = routing ?: return SecureRoutingReceiver.Outcome(droppedReason = "routing mode not configured")
        return r.onDatagram(frame)
    }

    /** Sends a verified inner packet to a tunnel session. */
    @Synchronized
    fun sendToSession(sessionId: Int, inner: ByteArray): ByteArray? {
        checkOpen()
        return sessions.sendToSession(sessionId, inner)
    }

    /** Builds keepalive datagrams for all sessions, paired with the endpoint to send to. */
    @Synchronized
    fun keepAliveFrames(): List<Pair<Endpoint, ByteArray>> {
        checkOpen()
        return sessions.keepAliveFrames().map { (info, frame) -> info.endpoint to frame }
    }

    @Synchronized
    fun closeSession(sessionId: Int): ByteArray? {
        checkOpen()
        return sessions.closeSession(sessionId, io.bms.knxsecure.session.CloseReason.ADMIN)
    }

    fun stats(): GatewayStatsView = GatewayStatsView(
        sessions = sessions.stats(),
        timeSync = routing?.timeGuard()?.snapshot(),
        routingSyncsSent = routing?.syncsSentCount() ?: 0,
    )

    fun sessionInfos(): List<io.bms.knxsecure.session.SessionInfo> = sessions.establishedSessions()

    override fun close() {
        closed = true
    }

    private fun checkOpen() {
        check(!closed) { "gateway is closed" }
    }
}

data class GatewayStatsView(
    val sessions: io.bms.knxsecure.session.GatewayStats,
    val timeSync: TimeSyncGuard.Stats?,
    val routingSyncsSent: Long,
)
