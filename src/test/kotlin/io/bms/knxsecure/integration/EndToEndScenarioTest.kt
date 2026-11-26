package io.bms.knxsecure.integration

import io.bms.knxsecure.demo.SimHarness
import io.bms.knxsecure.multicast.TimeSyncGuard
import io.bms.knxsecure.session.GatewayPolicy
import io.bms.knxsecure.sim.SimRoutingDevice
import io.bms.knxsecure.sim.SimPasswords
import io.bms.knxsecure.wire.SecureFrames
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Full-stack scenarios: simulated panels and backbone devices talking to the real
 * [io.bms.knxsecure.SecureGateway] through the simulated wire, using the real wire format.
 *
 * These are the executable version of `gradle demo` and cover the assignment's acceptance
 * scenarios end to end.
 */
class EndToEndScenarioTest {

    @Test
    fun `floor power-on - 200 panels establish and pass traffic`() {
        val h = SimHarness(policy = GatewayPolicy(maxSessions = 256), routing = false)
        val panels = (0 until 200).map { h.panel("P$it", 42000 + it, 0x3000L + it, 0x1200 + it) }
        panels.forEach { it.connect(h.gatewayEndpoint) }
        h.pumpPanels(panels)
        h.pumpPanels(panels)
        assertEquals(200, panels.count { it.isConnected })
        assertEquals(200, h.gateway.stats().sessions.established)

        // Every panel can write to the bus.
        h.net.clearBus()
        for (p in panels) p.writeGroup(h.gatewayEndpoint, 0x0a01, 0x01)
        h.pump()
        assertEquals(200, h.net.busTraffic().size, "every powered-on panel must be able to write")
        assertEquals(0, h.gateway.stats().sessions.totalDropped)
    }

    @Test
    fun `session exhaustion - spoofed flood does not block a real client`() {
        val h = SimHarness(
            policy = GatewayPolicy(maxSessions = 8, maxPendingHandshakes = 64, maxPendingPerSource = 64),
            routing = false,
        )
        val spoof = (0 until 500).map { i ->
            h.panel("s$i", 0, 0x5000L + i, 0).also { it.connect(h.gatewayEndpoint) }
        }
        h.pumpPanels(spoof)
        assertEquals(0, h.gateway.stats().sessions.established, "unauthenticated flood must consume no tunnel slot")

        val real = h.panel("real", 44000, 0x9999L, 0x1101)
        real.connect(h.gatewayEndpoint)
        h.pumpPanels(listOf(real))
        assertTrue(real.isConnected, "a legitimate client must still get through a flood")
    }

    @Test
    fun `night mode - sessions and routing time survive long quiet periods`() {
        val h = SimHarness(policy = GatewayPolicy(sessionIdleTimeoutMs = 20 * 60_000), routing = true)
        val panel = h.panel("N1", 43001, 0x4001L, 0x1301)
        panel.connect(h.gatewayEndpoint); h.pump(); h.pumpPanels(listOf(panel))

        val guard = h.gateway.routing!!.timeGuard()
        repeat(3) { i -> h.clock.advanceBy(1); h.net.broadcastMulticast(SecureFrames.groupSync(SimPasswords.groupKey, 1_000_000L + i, 1, i + 1)); h.pump() }

        // Energy-saving schedule: heartbeats stretched to every 10 minutes, for six hours.
        // The 20-minute idle timeout must tolerate this; only a truly silent session expires.
        val nightHeartbeatMs = 10 * 60_000L
        repeat(36) {
            h.clock.advanceBy(nightHeartbeatMs)
            panel.keepAlive(h.gatewayEndpoint); h.pump()
        }
        assertEquals(1, h.gateway.stats().sessions.established, "a nightly-heartbeat session survives the long gap")

        h.net.clearBus()
        val dev = SimRoutingDevice("B", SimPasswords.groupKey, 0x77L, h.clock, initialGroupTime = 1_000_000L + 6 * 60 * 60 * 1000L)
        h.net.broadcastMulticast(dev.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a10, 1))); h.pump()
        assertEquals(1, h.net.busTraffic().size, "routing traffic after the quiet period is delivered")
    }

    @Test
    fun `forged future timer notify cannot silence the segment`() {
        val h = SimHarness(routing = true)
        val guard = h.gateway.routing!!.timeGuard()
        val honest = (0 until 3).map {
            SimRoutingDevice("H$it", SimPasswords.groupKey, 0x100L + it, h.clock, initialGroupTime = 5_000_000L)
        }
        repeat(3) { i ->
            h.clock.advanceBy(1)
            honest[i].announce(5_000_000L + i).let { h.net.broadcastMulticast(it) }
            h.pump()
        }

        val attacker = SimRoutingDevice("X", SimPasswords.groupKey, 0xbadL, h.clock)
        h.net.broadcastMulticast(attacker.announce(5_000_000L + 3_600_000)); h.pump()
        assertEquals(0, guard.snapshot().forwardDriftMs)

        h.net.clearBus()
        var delivered = 0
        repeat(10) { i ->
            h.clock.advanceBy(50)
            honest.forEach { it.advance(50) }
            h.net.broadcastMulticast(honest[i % 3].publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a01, 1))); h.pump()
            delivered += h.net.busTraffic().size; h.net.clearBus()
        }
        assertEquals(10, delivered, "the forgery must not have silenced the segment")
        assertTrue(h.alarms.any { it.first == TimeSyncGuard.Alarm.FORWARD_JUMP_REFUSED })
    }

    @Test
    fun `sustained corroborated attack is bounded and legitimate traffic keeps flowing`() {
        val h = SimHarness(
            routing = true,
            timeSyncConfig = TimeSyncGuard.Config(
                minCorroboratingSenders = 3, forwardBurstCapMs = 2000, maxForwardStepMs = 2000,
                slewPerSecondMs = 10.0, maxTotalForwardDriftMs = 2000,
            ),
        )
        val guard = h.gateway.routing!!.timeGuard()
        repeat(3) { i -> h.clock.advanceBy(1); h.net.broadcastMulticast(SecureFrames.groupSync(SimPasswords.groupKey, 5_000_000L + i, 1, i + 1)); h.pump() }
        val start = guard.groupTimeNow()

        val colluders = (0 until 3).map { SimRoutingDevice("R$it", SimPasswords.groupKey, 0x9000L + it, h.clock) }
        repeat(3000) { i ->
            h.net.broadcastMulticast(colluders[i % 3].announce(guard.groupTimeNow() + 30_000)); h.pump()
            h.clock.advanceBy(100)
        }
        val drift = guard.snapshot().forwardDriftMs
        assertTrue(drift <= 2000, "forward drift must be capped within one tolerance, was $drift")
        assertTrue(guard.isDriftCeilingReached())

        // A real device publishing at true group time must still be delivered.
        h.net.clearBus()
        val good = SimRoutingDevice("G", SimPasswords.groupKey, 0x5555L, h.clock, initialGroupTime = start + 300_000L)
        h.net.broadcastMulticast(good.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a01, 1))); h.pump()
        assertEquals(1, h.net.busTraffic().size, "a drift-capped clock must not reject true-time frames")
    }

    @Test
    fun `mass reboot - stale panels neither move the clock nor trip the alarm`() {
        val h = SimHarness(routing = true)
        val guard = h.gateway.routing!!.timeGuard()
        repeat(3) { i -> h.clock.advanceBy(1); h.net.broadcastMulticast(SecureFrames.groupSync(SimPasswords.groupKey, 5_000_000L + i, 1, i + 1)); h.pump() }
        h.clock.advanceBy(120_000)

        repeat(400) { i ->
            val rebooted = SimRoutingDevice("RB$i", SimPasswords.groupKey, 0x2000L + i, h.clock)
            h.net.broadcastMulticast(rebooted.announce(1L)); h.pump()
            h.clock.advanceBy(1)
        }
        assertEquals(0, guard.snapshot().forwardDriftMs, "a reboot storm must not move the clock")
        assertFalse(guard.isSuspectedInflated(), "a reboot storm must not look like an attack")

        // Normal traffic resumes.
        h.net.clearBus()
        val dev = SimRoutingDevice("B", SimPasswords.groupKey, 0x3a3aL, h.clock, initialGroupTime = guard.groupTimeNow())
        h.net.broadcastMulticast(dev.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a01, 1))); h.pump()
        assertEquals(1, h.net.busTraffic().size)
    }

    @Test
    fun `pending table evicts half-open entries rather than refusing new clients`() {
        val h = SimHarness(
            policy = GatewayPolicy(maxSessions = 8, maxPendingHandshakes = 32, maxPendingPerSource = 32),
            routing = false,
        )
        // Fill the pending table with spoofed half-open requests, interleaving a real client.
        repeat(200) { i ->
            val s = h.panel("s$i", 0, 0x7000L + i, 0)
            s.connect(h.gatewayEndpoint)
            h.pump()
        }
        val real = h.panel("real", 45000, 0x8888L, 0x1101)
        real.connect(h.gatewayEndpoint)
        h.pumpPanels(listOf(real))
        assertTrue(real.isConnected, "a legitimate client must not be locked out by a full pending table")
    }
}
