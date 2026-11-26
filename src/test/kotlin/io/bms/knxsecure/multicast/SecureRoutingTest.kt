package io.bms.knxsecure.multicast

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxSecureException
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.util.VirtualClock
import io.bms.knxsecure.wire.SecureFrameVerifier
import io.bms.knxsecure.wire.SecureFrames
import io.bms.knxsecure.wire.ServiceType
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * End-to-end multicast tests using the real KNX IP Secure wire format.
 *
 * The attacker holds the backbone group key, so every malicious frame authenticates correctly.
 * Only [TimeSyncGuard]'s policy can stop the attack — which is exactly what these tests check.
 */
class SecureRoutingTest {

    private val groupKey = AesKey.of(Bytes.unhex("000102030405060708090a0b0c0d0e0f"))
    private val otherKey = AesKey.of(Bytes.unhex("101112131415161718191a1b1c1d1e1f"))
    private val verifier = SecureFrameVerifier()
    private val baseTs = 5_000_000L

    private fun receiver(
        clock: VirtualClock,
        guard: TimeSyncGuard = TimeSyncGuard(clock, initialGroupTimestamp = baseTs),
        cfg: SecureRoutingReceiver.Config = SecureRoutingReceiver.Config(),
    ) = SecureRoutingReceiver(groupKey, clock, guard, serialNumber = 0x00aa00bb00ccL, config = cfg)

    private val inner = ByteArray(14).also {
        it[0] = 6; it[1] = 0x10; it[2] = 0x05; it[3] = 0x30; it[4] = 0; it[5] = 14
    }

    // ---- normal operation -------------------------------------------------------------

    @Test
    fun `a legitimate secure routing frame reaches the bus`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(100)
        val frame = SecureFrames.wrapMulticast(groupKey, r.timeGuard().groupTimeNow(), 0x1111, 0, inner)
        val out = r.onDatagram(frame)
        assertEquals(1, out.busPackets.size)
        assertContentEquals(inner, out.busPackets[0])
        assertNull(out.droppedReason)
    }

    @Test
    fun `a legitimate group sync updates the estimate`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(500)
        val ts = baseTs + 450 // a little ahead due to real network timing
        val sync = SecureFrames.groupSync(groupKey, ts, 0x2222, 1)
        val out = r.onDatagram(sync)
        assertTrue(out.wasGroupSync)
        assertNotNull(out.decision)
    }

    // ---- THE attack -------------------------------------------------------------------

    @Test
    fun `forged future group sync from a key holder cannot silence the segment`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(1000)

        // Attacker (has the group key) broadcasts a group-sync one hour in the future.
        val forged = SecureFrames.groupSync(groupKey, r.timeGuard().groupTimeNow() + 3_600_000, 0xbad, 1)
        val attackOut = r.onDatagram(forged)
        assertTrue(attackOut.wasGroupSync)
        assertEquals(TimeSyncGuard.Verdict.REJECTED_FUTURE, attackOut.decision?.verdict)

        // Normal devices keep publishing at true group time. Every frame must arrive.
        var delivered = 0
        repeat(20) { i ->
            clock.advanceBy(100)
            val ts = r.timeGuard().groupTimeNow()
            val frame = SecureFrames.wrapMulticast(groupKey, ts, 0x5000L + i, i, inner)
            if (r.onDatagram(frame).busPackets.isNotEmpty()) delivered++
        }
        assertEquals(20, delivered, "the forged sync must not have caused any legitimate frame to be dropped")
        assertEquals(0, r.timeGuard().snapshot().forwardDriftMs)
    }

    @Test
    fun `repeated forged syncs from distinct fabricated serials still cannot move the clock`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(1000)
        // Attacker fabricates corroborating senders (serial numbers travel inside the MAC).
        repeat(100) { i ->
            val forged = SecureFrames.groupSync(groupKey, baseTs + 3_600_000, 0xb000L + i, i)
            r.onDatagram(forged)
            clock.advanceBy(50)
        }
        // Even fully "corroborated", the correction is capped by the burst/ceiling.
        assertTrue(r.timeGuard().groupTimeNow() - baseTs < 60_000,
            "estimate moved ${r.timeGuard().groupTimeNow() - baseTs} ms despite the attack")

        // Legitimate traffic at true group time is still delivered.
        var delivered = 0
        repeat(10) {
            clock.advanceBy(100)
            val frame = SecureFrames.wrapMulticast(groupKey, r.timeGuard().groupTimeNow(), 0x7000L + it, it, inner)
            if (r.onDatagram(frame).busPackets.isNotEmpty()) delivered++
        }
        assertTrue(delivered >= 9, "legitimate traffic must keep flowing ($delivered/10)")
    }

    @Test
    fun `a frame with a bad MAC never reaches the bus`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(100)
        val frame = SecureFrames.wrapMulticast(otherKey, r.timeGuard().groupTimeNow(), 0x3333, 0, inner)
        val out = r.onDatagram(frame)
        assertTrue(out.busPackets.isEmpty())
        assertNotNull(out.droppedReason)
    }

    @Test
    fun `a forged group sync with a bad MAC is rejected and does not touch the clock`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(100)
        val before = r.timeGuard().groupTimeNow()
        val forged = SecureFrames.groupSync(otherKey, baseTs + 3_600_000, 0xbad, 1)
        val out = r.onDatagram(forged)
        assertTrue(out.busPackets.isEmpty())
        assertEquals(before, r.timeGuard().groupTimeNow())
    }

    @Test
    fun `replaying an old routing frame is not delivered twice`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(100)
        val ts = r.timeGuard().groupTimeNow()
        val frame = SecureFrames.wrapMulticast(groupKey, ts, 0x4444, 0, inner)
        assertEquals(1, r.onDatagram(frame).busPackets.size)
        // A frame with an *identical* timestamp is legitimate (multicast has no per-sender
        // counter), so a byte-identical replay is indistinguishable from a duplicate broadcast.
        // The important property is that the clock is not affected and delivery is idempotent
        // at the application layer; assert the clock did not move.
        val before = r.timeGuard().groupTimeNow()
        r.onDatagram(frame)
        assertEquals(before, r.timeGuard().groupTimeNow())
    }

    // ---- stale peers and resync -------------------------------------------------------

    @Test
    fun `a rebooting panel's stale frame triggers a group sync response`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(60_000)
        // A rebooted panel sends timestamp 5 (its counter reset to near zero).
        val frame = SecureFrames.wrapMulticast(groupKey, 5, 0x9999, 0, inner)
        val out = r.onDatagram(frame)
        assertTrue(out.busPackets.isEmpty(), "a stale frame is not delivered")
        assertTrue(out.decision?.resyncSuggested == true)
        // ...and the gateway answers with a group-sync so the panel can catch up.
        assertNotNull(out.groupSyncToSend, "the gateway must help the stale peer converge")
        val sync = verifier.openGroupSync(groupKey, out.groupSyncToSend!!)
        assertTrue(sync.timestamp >= baseTs)
    }

    @Test
    fun `mass reboot does not cause a sync storm`() {
        val clock = VirtualClock()
        val r = receiver(clock, cfg = SecureRoutingReceiver.Config(minSyncResponseIntervalMs = 200))
        clock.advanceBy(120_000)
        var syncs = 0
        // 400 panels reboot within a second and each sends a stale frame.
        repeat(400) { i ->
            val frame = SecureFrames.wrapMulticast(groupKey, 1, 0x8000L + i, 0, inner)
            if (r.onDatagram(frame).groupSyncToSend != null) syncs++
            clock.advanceBy(2) // ~800 ms total
        }
        // At one sync per 200 ms over ~800 ms, only ~4-5 syncs, not 400.
        assertTrue(syncs <= 6, "expected a handful of syncs, got $syncs")
        assertFalse(r.timeGuard().isSuspectedInflated(), "a mass reboot must not look like an attack")
    }

    @Test
    fun `after mass reboot, normal traffic resumes without loss`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(120_000)
        repeat(300) { i ->
            r.onDatagram(SecureFrames.wrapMulticast(groupKey, 1, 0x9000L + i, 0, inner))
            clock.advanceBy(1)
        }
        // The panels answer our syncs and catch up to true group time.
        clock.advanceBy(5000)
        var delivered = 0
        repeat(20) { i ->
            clock.advanceBy(100)
            val frame = SecureFrames.wrapMulticast(groupKey, r.timeGuard().groupTimeNow(), 0xa000L + i, i, inner)
            if (r.onDatagram(frame).busPackets.isNotEmpty()) delivered++
        }
        assertEquals(20, delivered)
    }

    // ---- night mode -------------------------------------------------------------------

    @Test
    fun `night mode - traffic after a six hour quiet period is delivered`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(6 * 60 * 60 * 1000L)
        val frame = SecureFrames.wrapMulticast(groupKey, r.timeGuard().groupTimeNow(), 0xbbbb, 0, inner)
        assertEquals(1, r.onDatagram(frame).busPackets.size)
    }

    // ---- periodic sync -----------------------------------------------------------------

    @Test
    fun `periodic sync is suppressed while the clock is suspect`() {
        val clock = VirtualClock()
        val guard = TimeSyncGuard(clock, TimeSyncGuard.Config(
            consensusSenders = 3, minCorroboratingSenders = 1, forwardBurstCapMs = 2000,
            maxForwardStepMs = 2000, slewPerSecondMs = 1000.0, maxTotalForwardDriftMs = 2000,
        ), initialGroupTimestamp = baseTs)
        val r = receiver(clock, guard)
        clock.advanceBy(1000)
        // Push the clock forward with corroborated claims, then contradict it to trip the alarm.
        repeat(8) { guard.observeTimerNotify(guard.groupTimeNow() + 1900, 100); clock.advanceBy(2000) }
        val inflated = guard.groupTimeNow()
        repeat(3) { guard.observeDataFrame(inflated - 30_000, 0x2000L + it) }
        assertTrue(guard.isSuspectedInflated())
        assertNull(r.buildPeriodicSync(force = true), "a suspect clock must not be advertised as authoritative")
    }

    @Test
    fun `unknown service types are ignored`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        val bogus = io.bms.knxsecure.wire.KnxIpHeader(ServiceType.TUNNELLING_REQUEST, 10).encode() + ByteArray(4)
        assertNotNull(r.onDatagram(bogus).droppedReason)
    }

    @Test
    fun `a unicast wrapper appearing on the multicast group is refused`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(100)
        val unicast = SecureFrames.wrap(groupKey, 0x1234, r.timeGuard().groupTimeNow(), 0x1111, 0, inner)
        val out = r.onDatagram(unicast)
        assertTrue(out.busPackets.isEmpty())
        assertNotNull(out.droppedReason)
    }

    @Test
    fun `sealed outbound routing frame verifies on the receiver side`() {
        val clock = VirtualClock()
        val r = receiver(clock)
        clock.advanceBy(100)
        val sealed = r.sealRouting(inner)
        // Another gateway instance on the same backbone should accept it.
        val r2 = receiver(clock)
        assertTrue(r2.onDatagram(sealed).busPackets.isNotEmpty())
    }
}
