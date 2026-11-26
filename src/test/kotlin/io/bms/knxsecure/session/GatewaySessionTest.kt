package io.bms.knxsecure.session

import io.bms.knxsecure.SecureGateway
import io.bms.knxsecure.client.SecureTunnelClient
import io.bms.knxsecure.client.TunnelPackets
import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.Pbkdf2
import io.bms.knxsecure.util.VirtualClock
import io.bms.knxsecure.wire.Endpoint
import io.bms.knxsecure.wire.SessionStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * End-to-end gateway tests driven by the reference-faithful client.
 *
 * These cover the happy path, replay defence, cross-session injection and the session
 * exhaustion attack, including the legitimate mass power-on that must NOT be mistaken for it.
 */
class GatewaySessionTest {

    private val userKey = Pbkdf2.userKey("installer-pw")
    private val deviceKey = Pbkdf2.deviceAuthKey("device-code-1234")

    private fun gateway(
        clock: VirtualClock,
        policy: GatewayPolicy = GatewayPolicy(),
        maxSessions: Int = 256,
    ): SecureGateway = SecureGateway(
        credentials = GatewayCredentials(
            deviceAuthKey = AesKey.of(deviceKey),
            users = listOf(UserAccount(1, userKey), UserAccount(2, Pbkdf2.userKey("second-tenant"))),
        ),
        clock = clock,
        policy = policy.copy(maxSessions = maxSessions),
        serialNumber = 0x010203040506L,
    )

    private fun client(port: Int, password: String = "installer-pw", serial: Long = 0x0a0b0c0d0e0fL) =
        SecureTunnelClient.withPassword(
            endpoint = Endpoint.of("10.0.0.${port % 250 + 1}", port),
            userId = 1,
            password = password,
            deviceAuthPassword = "device-code-1234",
            serialNumber = serial,
        )

    /** Runs the full handshake and returns the established session id. */
    private fun handshake(gw: SecureGateway, c: SecureTunnelClient): Int {
        val response = gw.onUnicast(c.endpoint, c.buildSessionRequest())
        assertEquals(1, response.responses.size, "expected a session response")
        val auth = c.onSessionResponse(response.responses[0])
        val status = gw.onUnicast(c.endpoint, auth)
        assertEquals(1, status.responses.size, "expected a session status")
        assertEquals(SessionStatus.AUTH_SUCCESS, c.onStatusFrame(status.responses[0]))
        return c.sessionId
    }

    // ---- happy path -----------------------------------------------------------------

    @Test
    fun `handshake establishes a session both sides agree on`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1001)
        val id = handshake(gw, c)
        assertTrue(id > 0)
        assertTrue(c.isEstablished())
        assertEquals(1, gw.sessionInfos().size)
        assertEquals(id, gw.sessionInfos()[0].sessionId)
        assertEquals(Endpoint.of("10.0.0.2", 1001), gw.sessionInfos()[0].endpoint)
    }

    @Test
    fun `tunnel data flows in both directions with sequence numbers`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1002)
        val id = handshake(gw, c)

        val inner = TunnelPackets.tunnelingRequest(1, 0, TunnelPackets.groupWriteCemi(0x0a01, 0x01))
        val frame = c.seal(inner)
        val out = gw.onUnicast(c.endpoint, frame)
        assertEquals(1, out.busPackets.size)
        assertTrue(out.busPackets[0].contentEquals(inner))

        val downlink = gw.sendToSession(id, inner)
        assertNotNull(downlink)
        assertTrue(c.open(downlink).contentEquals(inner))
    }

    // ---- authentication -------------------------------------------------------------

    @Test
    fun `wrong user password is rejected and the session never establishes`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1003, password = "wrong-password")
        val response = gw.onUnicast(c.endpoint, c.buildSessionRequest())
        val auth = c.onSessionResponse(response.responses[0])
        // The auth itself is answered with a (wrapped, unreadable-to-us) failure or silence.
        gw.onUnicast(c.endpoint, auth)
        assertTrue(gw.sessionInfos().isEmpty(), "no session may be established")
    }

    @Test
    fun `client rejects a gateway that cannot prove the device key`() {
        val clock = VirtualClock()
        // Gateway configured with a *different* device code: it is an impostor from the client's view.
        val gw = SecureGateway(
            credentials = GatewayCredentials(
                deviceAuthKey = AesKey.of(Pbkdf2.deviceAuthKey("attacker-device-code")),
                users = listOf(UserAccount(1, userKey)),
            ),
            clock = clock,
        )
        val c = client(1004)
        val response = gw.onUnicast(c.endpoint, c.buildSessionRequest())
        val ex = runCatching { c.onSessionResponse(response.responses[0]) }.exceptionOrNull()
        assertNotNull(ex, "client must reject an unauthenticated session response")
        assertFalse(c.isEstablished())
    }

    // ---- replay / injection -----------------------------------------------------------

    @Test
    fun `duplicate data frame is rejected`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1005)
        handshake(gw, c)

        val inner = TunnelPackets.tunnelingRequest(1, 0, TunnelPackets.groupWriteCemi(0x0a02, 0x01))
        val frame = c.seal(inner)
        assertEquals(1, gw.onUnicast(c.endpoint, frame).busPackets.size)
        val replay = gw.onUnicast(c.endpoint, frame)
        assertTrue(replay.busPackets.isEmpty(), "a replayed frame must not reach the bus")
        assertEquals("replay", replay.droppedReason)
    }

    @Test
    fun `replayed frame after newer traffic is rejected`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1006)
        handshake(gw, c)
        val inner = TunnelPackets.tunnelingRequest(1, 0, TunnelPackets.groupWriteCemi(0x0a03, 0x01))
        val first = c.seal(inner)
        assertEquals(1, gw.onUnicast(c.endpoint, first).busPackets.size, "first delivery must succeed")
        repeat(5) { _ -> gw.onUnicast(c.endpoint, c.seal(inner)) }
        // Replaying the *already delivered* frame is a replay, even though it is inside the window.
        assertTrue(gw.onUnicast(c.endpoint, first).busPackets.isEmpty())
    }

    @Test
    fun `out of order delivery within the window is accepted exactly once`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1010)
        handshake(gw, c)
        val inner = TunnelPackets.tunnelingRequest(1, 0, TunnelPackets.groupWriteCemi(0x0a06, 0x01))
        val f0 = c.seal(inner)
        val f1 = c.seal(inner)
        val f2 = c.seal(inner)
        // Deliver 0, 2, 1: UDP reordering must not silently drop a legitimate frame.
        assertEquals(1, gw.onUnicast(c.endpoint, f0).busPackets.size)
        assertEquals(1, gw.onUnicast(c.endpoint, f2).busPackets.size)
        assertEquals(1, gw.onUnicast(c.endpoint, f1).busPackets.size)
        // ...but each frame is still accepted only once.
        assertTrue(gw.onUnicast(c.endpoint, f1).busPackets.isEmpty())
    }

    @Test
    fun `frame with a valid session id but from another endpoint is refused`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1007)
        handshake(gw, c)
        val frame = c.seal(TunnelPackets.tunnelingRequest(1, 0, TunnelPackets.groupWriteCemi(0x0a04, 0x01)))
        val attacker = Endpoint.of("10.9.9.9", 4444)
        val out = gw.onUnicast(attacker, frame)
        assertTrue(out.busPackets.isEmpty())
        assertEquals("endpoint mismatch", out.droppedReason)
    }

    @Test
    fun `tampered ciphertext does not reach the bus`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(1008)
        handshake(gw, c)
        val frame = c.seal(TunnelPackets.tunnelingRequest(1, 0, TunnelPackets.groupWriteCemi(0x0a05, 0x01)))
        val tampered = frame.copyOf().also { it[it.size - 5] = (it[it.size - 5].toInt() xor 0x40).toByte() }
        assertTrue(gw.onUnicast(c.endpoint, tampered).busPackets.isEmpty())
    }

    // ---- session exhaustion -----------------------------------------------------------

    @Test
    fun `spoofed half-open handshakes cannot occupy tunnel slots`() {
        val clock = VirtualClock()
        val gw = gateway(clock, maxSessions = 8, policy = GatewayPolicy(maxSessions = 8, maxPendingHandshakes = 4096, maxPendingPerSource = 4096))

        // 3000 distinct spoofed sources fire session requests that never authenticate.
        repeat(3000) { i ->
            val fake = client(2000 + i)
            gw.onUnicast(fake.endpoint, fake.buildSessionRequest())
            clock.advanceBy(1)
        }

        // No tunnel slot may be occupied by an unauthenticated request.
        assertEquals(0, gw.stats().sessions.established)
        // Yet a real client must still get in.
        val real = client(1999)
        handshake(gw, real)
        assertEquals(1, gw.stats().sessions.established)
    }

    @Test
    fun `half-open handshakes expire and free the pending table`() {
        val clock = VirtualClock()
        val policy = GatewayPolicy(maxPendingHandshakes = 8, handshakeTimeoutMs = 10_000, maxPendingPerSource = 8)
        val gw = gateway(clock, policy = policy)
        repeat(8) { i ->
            val fake = client(3000 + i)
            gw.onUnicast(fake.endpoint, fake.buildSessionRequest())
        }
        assertEquals(8, gw.stats().sessions.pendingHandshakes)
        clock.advanceBy(11_000)
        // A no-op datagram triggers the sweep.
        gw.onUnicast(Endpoint.of("1.2.3.4", 1), ByteArray(2))
        assertEquals(0, gw.stats().sessions.pendingHandshakes)
    }

    @Test
    fun `handshake flood is rate limited per source`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val source = Endpoint.of("10.5.5.5", 5000)
        var sent = 0
        var admitted = 0
        repeat(500) {
            val c = SecureTunnelClient.withPassword(source, 1, "installer-pw", "device-code-1234", 0x111L)
            val r = gw.onUnicast(source, c.buildSessionRequest())
            sent++
            if (r.responses.isNotEmpty()) admitted++
        }
        assertTrue(admitted < sent, "flood must be throttled")
        assertTrue(admitted <= 60, "at most the burst allowance plus a little should pass")
    }

    @Test
    fun `mass power-on of many distinct panels all establish`() {
        val clock = VirtualClock()
        val gw = gateway(clock, maxSessions = 256)
        val clients = (0 until 200).map { client(4000 + it, serial = 0x1000L + it) }
        // Simulate a simultaneous energisation burst, all within ~1 second.
        for (c in clients) {
            val response = gw.onUnicast(c.endpoint, c.buildSessionRequest())
            assertTrue(response.responses.isNotEmpty(), "power-on request must be admitted")
            val auth = c.onSessionResponse(response.responses[0])
            val status = gw.onUnicast(c.endpoint, auth)
            assertEquals(SessionStatus.AUTH_SUCCESS, c.onStatusFrame(status.responses[0]))
            clock.advanceBy(2)
        }
        assertEquals(200, gw.stats().sessions.established)
        assertTrue(clients.all { it.isEstablished() })
    }

    @Test
    fun `session table full evicts the least recently used idle session`() {
        val clock = VirtualClock()
        val gw = gateway(clock, maxSessions = 4, policy = GatewayPolicy(maxSessions = 4, minEvictableIdleMs = 1000))
        val first = (0 until 4).map { client(5000 + it, serial = 0x2000L + it) }
        for (c in first) handshake(gw, c)
        assertEquals(4, gw.stats().sessions.established)

        // All four go idle for a while; a new client arrives and should evict the oldest.
        clock.advanceBy(5_000)
        first.drop(1).forEach { c ->
            gw.onUnicast(c.endpoint, c.buildKeepAlive())
            clock.advanceBy(10)
        }
        val newcomer = client(5999, serial = 0x9999L)
        handshake(gw, newcomer)
        assertEquals(4, gw.stats().sessions.established)
        assertTrue(newcomer.isEstablished())
        // The very first client (longest idle) should have been evicted.
        assertTrue(gw.sessionInfos().none { it.endpoint == first[0].endpoint })
    }

    @Test
    fun `night mode - idle session survives a long heartbeat gap`() {
        val clock = VirtualClock()
        val gw = gateway(clock, policy = GatewayPolicy(sessionIdleTimeoutMs = 20 * 60_000))
        val c = client(6001)
        handshake(gw, c)

        // 15 minutes of silence: well beyond typical keepalive intervals but inside the timeout.
        clock.advanceBy(15 * 60_000)
        val out = gw.onUnicast(c.endpoint, c.buildKeepAlive())
        assertTrue(out.accepted, "a keepalive after a long gap must be accepted")
        assertEquals(1, gw.stats().sessions.established)
    }

    @Test
    fun `idle session is reaped after the timeout`() {
        val clock = VirtualClock()
        val gw = gateway(clock, policy = GatewayPolicy(sessionIdleTimeoutMs = 60_000))
        val c = client(6002)
        handshake(gw, c)
        clock.advanceBy(61_000)
        gw.onUnicast(Endpoint.of("1.2.3.4", 1), ByteArray(2)) // triggers the sweep
        assertEquals(0, gw.stats().sessions.established)
    }

    @Test
    fun `unknown session ids are dropped without a response`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(6003)
        handshake(gw, c)
        // A wrapper for a session id that does not exist.
        val bogus = io.bms.knxsecure.wire.SecureFrames.wrap(
            AesKey.of(ByteArray(16) { 1 }), 0x7777, 0, 0x123456789abcL, 0, ByteArray(8) { 2 },
        )
        val out = gw.onUnicast(c.endpoint, bogus)
        assertTrue(out.responses.isEmpty())
        assertEquals("unknown session", out.droppedReason)
    }

    @Test
    fun `close request from peer tears down the session`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(6004)
        handshake(gw, c)
        val out = gw.onUnicast(c.endpoint, c.buildClose())
        assertTrue(out.accepted)
        assertEquals(0, gw.stats().sessions.established)
    }

    @Test
    fun `malformed and short datagrams are dropped safely`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val src = Endpoint.of("10.1.1.1", 1234)
        assertFalse(gw.onUnicast(src, ByteArray(0)).accepted)
        assertFalse(gw.onUnicast(src, ByteArray(3)).accepted)
        assertFalse(gw.onUnicast(src, ByteArray(6)).accepted)
        val huge = byteArrayOf(
            6, 0x10, 0x09, 0x51, 0xff.toByte(), 0xff.toByte(),
        ) + ByteArray(10)
        assertFalse(gw.onUnicast(src, huge).accepted)
    }

    // ---- keepalive -------------------------------------------------------------------

    @Test
    fun `gateway keepalive frames are decryptable by the client`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(7001)
        handshake(gw, c)
        val frames = gw.keepAliveFrames()
        assertEquals(1, frames.size)
        val inner = c.open(frames[0].second)
        assertEquals(SessionStatus.KEEP_ALIVE, io.bms.knxsecure.wire.SessionMessages.decodeStatusInner(inner))
    }

    @Test
    fun `administrative close sends a wrapped close status`() {
        val clock = VirtualClock()
        val gw = gateway(clock)
        val c = client(7002)
        val id = handshake(gw, c)
        val frame = gw.closeSession(id)
        assertNotNull(frame)
        assertEquals(SessionStatus.CLOSE, io.bms.knxsecure.wire.SessionMessages.decodeStatusInner(c.open(frame)))
        assertEquals(0, gw.stats().sessions.established)
        assertNull(gw.sendToSession(id, ByteArray(6)))
    }
}
