package io.bms.knxsecure.multicast

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.util.VirtualClock
import io.bms.knxsecure.wire.SecureFrames
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for the multicast time base.
 *
 * The attacker model: they hold the backbone group key (a compromised field device, a
 * leaked key, or a mis-configured node), so every attack frame here has a **valid MAC**.
 * Cryptographic authentication therefore cannot help; only the policy in [TimeSyncGuard] can.
 */
class TimeSyncGuardTest {

    private val baseTs = 1_000_000L

    private fun guard(
        clock: VirtualClock,
        config: TimeSyncGuard.Config = TimeSyncGuard.Config(),
        initial: Long? = baseTs,
    ) = TimeSyncGuard(clock, config, initial)

    // ---- bootstrap -------------------------------------------------------------------

    @Test
    fun `anchors to the minimum of the bootstrap window`() {
        val clock = VirtualClock()
        val g = TimeSyncGuard(clock, TimeSyncGuard.Config(bootstrapSamples = 3), initialGroupTimestamp = null)
        assertEquals(TimeSyncGuard.Verdict.BOOTSTRAP_PENDING, g.observeTimerNotify(baseTs + 50_000, 1).verdict)
        assertEquals(TimeSyncGuard.Verdict.BOOTSTRAP_PENDING, g.observeTimerNotify(baseTs, 2).verdict)
        // A forged future frame inside the bootstrap window must not win: the anchor is the MIN.
        val d = g.observeTimerNotify(baseTs + 1, 3)
        assertEquals(TimeSyncGuard.Verdict.BOOTSTRAPPED, d.verdict)
        assertEquals(baseTs, g.groupTimeNow())
    }

    // ---- the core attack --------------------------------------------------------------

    @Test
    fun `a single forged future notification cannot push the estimate forward`() {
        val clock = VirtualClock()
        val g = guard(clock)
        clock.advanceBy(1000)
        // Attacker claims the group is one hour in the future.
        val forged = baseTs + 1_000 + 3_600_000
        val d = g.observeTimerNotify(forged, senderSerial = 0xdead)
        assertEquals(TimeSyncGuard.Verdict.REJECTED_FUTURE, d.verdict)
        // The estimate must not have jumped: it tracks local time only.
        assertEquals(baseTs + 1_000, g.groupTimeNow().let { it - 0 } )
        assertEquals(0, g.snapshot().forwardDriftMs)
    }

    @Test
    fun `legitimate frames are still delivered after the forged future notification`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(minCorroboratingSenders = 3))
        clock.advanceBy(1000)
        g.observeTimerNotify(baseTs + 1_000 + 3_600_000, 0xbad)

        // Every real device keeps sending frames at roughly local group time.
        repeat(50) { i ->
            clock.advanceBy(100)
            val d = g.observeDataFrame(baseTs + 1_000 + (i + 1) * 100, 0x1000L + i)
            assertTrue(d.deliverable, "legitimate frame $i must be deliverable after the attack")
        }
        assertEquals(0, g.snapshot().forwardDriftMs, "the forgery must not have moved the clock")
    }

    @Test
    fun `a stream of forged notifications is slew limited`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            maxForwardStepMs = 2000, forwardBurstCapMs = 2000, slewPerSecondMs = 10.0,
            maxTotalForwardDriftMs = 2000, minCorroboratingSenders = 3,
        ))
        clock.advanceBy(1000)
        val anchor = g.groupTimeNow()
        // 60 seconds of a forged future-dated timer notification every 100 ms.
        repeat(600) {
            val claim = g.groupTimeNow() + 30_000
            g.observeTimerNotify(claim, 0xbad)
            clock.advanceBy(100)
        }
        // A lone sender (never corroborated) must not have moved the estimate at all: the only
        // change is the real elapsed local time.
        assertEquals(0, g.snapshot().forwardDriftMs, "a lone attacker must not move the clock")
        assertEquals(anchor + 60_000, g.groupTimeNow(), "estimate advanced only by real elapsed time")
    }

    @Test
    fun `corroborated flood cannot exceed the slew budget plus burst`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            maxForwardStepMs = 2000, forwardBurstCapMs = 2000, slewPerSecondMs = 10.0,
            maxTotalForwardDriftMs = 2000, minCorroboratingSenders = 3,
        ))
        clock.advanceBy(1000)
        val anchor = g.groupTimeNow()
        // Same flood, but now three colluding senders (e.g. a compromised VLAN) corroborate.
        repeat(600) { i ->
            val claim = g.groupTimeNow() + 30_000
            g.observeTimerNotify(claim, 0xbad0L + (i % 3))
            clock.advanceBy(100)
        }
        val drift = g.snapshot().forwardDriftMs
        // 60 s at 10 ms/s = 600 ms of slew, plus the 2000 ms burst: well under a minute.
        assertTrue(drift <= 2000 + 600 + 100, "corroborated drift $drift must stay slew bounded")
        assertTrue(g.groupTimeNow() - anchor <= 60_000 + 2000 + 700)
    }

    @Test
    fun `drift ceiling latches and stops all forward motion`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            forwardBurstCapMs = 2000, maxForwardStepMs = 2000, slewPerSecondMs = 1000.0,
            maxTotalForwardDriftMs = 2000, minCorroboratingSenders = 1,
        ))
        clock.advanceBy(10_000)
        // Repeated small forward claims that are individually plausible.
        repeat(20) {
            g.observeTimerNotify(g.groupTimeNow() + 1500, 0xbad)
            clock.advanceBy(2000)
        }
        assertTrue(g.isDriftCeilingReached(), "ceiling should latch once cumulative drift is exhausted")
        val frozen = g.groupTimeNow()
        clock.advanceBy(2000)
        val d = g.observeTimerNotify(g.groupTimeNow() + 5000, 0xbad)
        assertEquals(TimeSyncGuard.Verdict.REJECTED_BUDGET, d.verdict)
        // The estimate may only advance by real elapsed time, not by the claim.
        assertTrue(g.groupTimeNow() - frozen <= 2000 + 1)
    }

    @Test
    fun `corroborated large correction is still bounded`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            minCorroboratingSenders = 3, forwardBurstCapMs = 2000, maxForwardStepMs = 2000,
            maxTotalForwardDriftMs = 2000,
        ))
        clock.advanceBy(1000)
        val big = g.groupTimeNow() + 60_000
        // Three distinct senders corroborate.
        g.observeTimerNotify(big, 1)
        g.observeTimerNotify(big, 2)
        val d = g.observeTimerNotify(big, 3)
        assertEquals(TimeSyncGuard.Verdict.CORRECTED, d.verdict)
        // Even fully corroborated, the correction is capped by the burst/ceiling, not 60 s.
        assertTrue(g.groupTimeNow() - (baseTs + 1000) <= 2000)
    }

    @Test
    fun `suspected inflation is alarmed after real forward drift is contradicted`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            consensusSenders = 3, latencyToleranceMs = 2000, minCorroboratingSenders = 1,
            forwardBurstCapMs = 2000, maxForwardStepMs = 2000, slewPerSecondMs = 1000.0,
            maxTotalForwardDriftMs = 2000,
        ))
        val alarms = ArrayList<TimeSyncGuard.Alarm>()
        g.onAlarm { a, _ -> alarms += a }

        // Walk the estimate forward with corroborated claims until it has real forward drift.
        repeat(8) {
            g.observeTimerNotify(g.groupTimeNow() + 1900, 100)
            clock.advanceBy(2000)
        }
        assertTrue(g.snapshot().forwardDriftMs > 0, "precondition: the clock was moved forward")

        val inflated = g.groupTimeNow()
        // Three honest devices report timestamps far behind the now-inflated estimate.
        repeat(3) { i ->
            val d = g.observeDataFrame(inflated - 30_000, 0x2000L + i)
            assertFalse(d.deliverable)
        }
        assertTrue(g.isSuspectedInflated())
        assertTrue(alarms.contains(TimeSyncGuard.Alarm.CLOCK_SUSPECTED_INFLATED))
        val d = g.observeDataFrame(g.groupTimeNow(), 0x2000L)
        assertFalse(d.mayActAsTimeKeeper)
    }

    // ---- legitimate scenarios ---------------------------------------------------------

    @Test
    fun `mass power-on - a burst of stale rebooting devices does not disturb the clock`() {
        val clock = VirtualClock()
        val g = guard(clock)
        clock.advanceBy(60_000)
        val before = g.groupTimeNow()
        // 500 panels reboot with a near-zero timestamp and announce themselves at once.
        repeat(500) { i ->
            val d = g.observeDataFrame(5, 0x3000L + i)
            // They are stale, so the caller is told to send a sync...
            assertTrue(d.resyncSuggested)
            assertFalse(d.deliverable)
        }
        // ...but the estimate itself never moved (backward claims never move it).
        assertEquals(before, g.groupTimeNow())
        assertFalse(g.isSuspectedInflated(), "a mass reboot is not evidence that our clock is inflated")
    }

    @Test
    fun `night mode - a long heartbeat gap does not make frames look expired`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(latencyToleranceMs = 2000))
        clock.advanceBy(1000)
        // The segment goes quiet for six hours (energy-saving schedule).
        clock.advanceBy(6 * 60 * 60 * 1000L)
        // Traffic resumes at true group time, which tracks local time.
        val d = g.observeDataFrame(baseTs + 1000 + 6 * 60 * 60 * 1000L, 0x4000)
        assertTrue(d.deliverable, "traffic after a long quiet period must still be fresh")
        assertEquals(TimeSyncGuard.Verdict.FRESH, d.verdict)
    }

    @Test
    fun `normal small jitter is accepted both ways`() {
        val clock = VirtualClock()
        val g = guard(clock)
        clock.advanceBy(1000)
        val now = g.groupTimeNow()
        assertTrue(g.observeDataFrame(now - 500, 1).deliverable)   // 500 ms late
        assertTrue(g.observeDataFrame(now + 300, 2).deliverable)   // 300 ms early (jitter)
        assertTrue(g.observeDataFrame(now + 100, 3).deliverable)
    }

    @Test
    fun `frame older than tolerance is dropped with a resync suggestion`() {
        val clock = VirtualClock()
        val g = guard(clock)
        clock.advanceBy(1000)
        val d = g.observeDataFrame(g.groupTimeNow() - 5000, 1)
        assertEquals(TimeSyncGuard.Verdict.TOO_OLD, d.verdict)
        assertFalse(d.deliverable)
        assertTrue(d.resyncSuggested)
    }

    @Test
    fun `estimate is monotonic even across clock samples`() {
        val clock = VirtualClock()
        val g = guard(clock)
        val seen = ArrayList<Long>()
        repeat(100) {
            clock.advanceBy(37)
            seen += g.groupTimeNow()
        }
        assertTrue(seen.zipWithNext().all { (a, b) -> b >= a }, "groupTimeNow must never go backwards")
    }

    @Test
    fun `implausibly high timestamp raises an alarm`() {
        val clock = VirtualClock()
        val g = guard(clock, initial = 0)
        val alarms = ArrayList<TimeSyncGuard.Alarm>()
        g.onAlarm { a, _ -> alarms += a }
        g.observeDataFrame(TimeSyncGuard.HIGH_TIMESTAMP, 1)
        assertTrue(alarms.contains(TimeSyncGuard.Alarm.IMPLAUSIBLE_HIGH_TIMESTAMP))
    }

    @Test
    fun `operator hard resync clears the ceiling`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            forwardBurstCapMs = 2000, maxForwardStepMs = 2000, slewPerSecondMs = 1000.0,
            maxTotalForwardDriftMs = 2000, minCorroboratingSenders = 1,
        ))
        clock.advanceBy(5000)
        repeat(5) { g.observeTimerNotify(g.groupTimeNow() + 1500, 1); clock.advanceBy(1000) }
        assertTrue(g.isDriftCeilingReached())
        g.hardResync(baseTs + 5000, "operator confirmed ETS download")
        assertFalse(g.isDriftCeilingReached())
        assertTrue(g.groupTimeNow() >= baseTs + 5000)
    }

    @Test
    fun `a genuinely fast-drifting group does not trip the ceiling over days`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            latencyToleranceMs = 2000, maxForwardStepMs = 2000, forwardBurstCapMs = 2000,
            maxTotalForwardDriftMs = 2000, slewPerSecondMs = 10.0, minCorroboratingSenders = 1,
            driftDecayPpm = 100, // 0.01 % ≈ 360 ms/hour, above realistic crystal skew
        ))
        // The group runs ~20 ppm fast (2 ms ahead every 100 s), a realistic crystal skew.
        // Over 24 hours this must be tracked indefinitely, never latching the ceiling.
        repeat(24 * 36) {
            clock.advanceBy(100_000)
            g.observeTimerNotify(g.groupTimeNow() + 2, 7)
        }
        assertFalse(g.isDriftCeilingReached(), "normal crystal skew must never latch the ceiling")
        assertFalse(g.isSuspectedInflated())
    }

    @Test
    fun `a sudden jump after a long healthy run is still refused`() {
        val clock = VirtualClock()
        val g = guard(clock, TimeSyncGuard.Config(
            latencyToleranceMs = 2000, maxForwardStepMs = 2000, forwardBurstCapMs = 2000,
            maxTotalForwardDriftMs = 2000, slewPerSecondMs = 10.0, minCorroboratingSenders = 3,
        ))
        // Run healthily for six hours: the group runs ~20 ppm fast (2 ms ahead every 100 s).
        repeat(6 * 36) { clock.advanceBy(100_000); g.observeTimerNotify(g.groupTimeNow() + 2, 7) }
        val beforeJump = g.groupTimeNow()

        // Attacker jumps an hour ahead, corroborated by three distinct senders.
        val jump = beforeJump + 3_600_000
        repeat(3) { i -> g.observeTimerNotify(jump, 0xbad0L + i); clock.advanceBy(10) }

        // The 3 600 000 ms claim must not propagate: at most the burst/ceiling (~2 s) is applied.
        val applied = g.groupTimeNow() - beforeJump
        assertTrue(applied <= 2_500, "a sudden jump propagated $applied ms despite the ceiling")
    }
}
