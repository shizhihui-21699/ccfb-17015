package io.bms.knxsecure.multicast

import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.util.MonotonicClock

/**
 * Hardened handling of the KNX IP Secure multicast (routing) time base.
 *
 * ## The mechanism being defended
 *
 * On a secure backbone every routing frame carries a 48-bit *group timestamp* instead of a
 * per-session sequence number. A receiver accepts a frame when its timestamp is no older
 * than a latency tolerance (KNX allows 1..8000 ms) relative to the receiver's estimate of
 * group time. The estimate is synchronised by `0x0955` group-sync / timer-notify frames,
 * which are authenticated only with the **shared backbone group key** — every secure
 * backbone device holds it, and the MAC proves key possession, not authority.
 *
 * So an attacker who holds (or extracts) the group key, or who is one compromised field
 * device, can announce a timestamp far in the future. A naive receiver applies the full
 * difference to its offset; every legitimate frame is then older than the tolerance and the
 * entire segment goes silent. That is the attack this class is built against.
 *
 * ## The key asymmetry
 *
 *  - A frame that is **ahead** of the estimate is *fresh*: it must be delivered (subject to
 *    its MAC). Rejecting ahead-frames protects nothing.
 *  - A frame that is **behind** the estimate is what the tolerance check drops.
 *
 * Therefore the only thing that can "silence" the segment is the estimate being too far
 * **ahead** of real group time. Every rule below exists to keep the estimate from moving
 * forward except in bounded, corroborated steps — and never to react to being *behind*,
 * because being behind is harmless: the frames still arrive ahead of us and are delivered.
 *
 * This also dissolves the long-heartbeat problem. Group time is `anchor + elapsed local
 * monotonic time`, not "the last timestamp we saw". During night / energy-saving operation
 * the heartbeat may be minutes or hours apart; the estimate keeps ticking, so traffic that
 * resumes is still within tolerance. And a segment that never sends a group-sync at all
 * still works, because frames are simply ahead of us.
 *
 * ## Rules
 *
 *  - **R1 — Ahead is deliverable.** Ahead-frames are never refused for being ahead.
 *  - **R2 — Bounded single step.** A single observation may move the estimate forward by at
 *    most [Config.maxForwardStepMs], which must not exceed the latency tolerance. Pushing the
 *    estimate by exactly the tolerance cannot strand legitimate frames (they become *at* the
 *    edge, which is still accepted) — this is why the cap is tied to the tolerance.
 *  - **R3 — Corroborate jumps.** A forward claim larger than the single step needs
 *    [Config.minCorroboratingSenders] distinct serial numbers within
 *    [Config.corroborationWindowMs]. A lone rogue node cannot move the clock at all.
 *    (Serial numbers travel inside the MAC, so an attacker with the group key can fabricate
 *    them; corroboration is defence in depth. R3/R4 provide the hard bound.)
 *  - **R4 — Slew + drift ceiling.** Forward corrections draw on a token bucket refilling at
 *    [Config.slewPerSecondMs] and are capped by [Config.maxTotalForwardDriftMs] of cumulative
 *    drift since the anchor. Crucially, that cap is itself required to be **no larger than the
 *    latency tolerance**: legitimate groups that run slightly *faster* than us need no
 *    correction at all (their frames are ahead and always accepted), so forward drift only
 *    ever helps an attacker. Keeping it within one tolerance guarantees that a genuine frame
 *    at true group time can never be pushed out of the acceptance window. A sustained attack
 *    therefore degrades the segment by at most a tolerance and then stops, with
 *    [Alarm.FORWARD_DRIFT_CEILING_REACHED] latched until an operator performs [hardResync].
 *  - **R5 — Monotonic output.** Network input never moves the estimate backwards, so the
 *    application never sees frames re-ordered by a clock change.
 *  - **R6 — Freeze once suspect.** If [Config.consensusSenders] distinct senders are all
 *    behind the estimate by more than the tolerance, the estimate is probably inflated. The
 *    guard freezes all forward correction, raises [Alarm.CLOCK_SUSPECTED_INFLATED], and
 *    refuses to emit our own timestamp as authoritative until a resync. Service for
 *    frames that are merely behind within tolerance is unaffected.
 *
 * ## Legitimate scenarios
 *
 *  - **A whole floor of panels powering on together.** Work per frame is O(1) plus a bounded
 *    sender scan; nothing is linear in burst size. Rebooting panels carry a stale (often
 *    near-zero) timestamp, get [Verdict.TOO_OLD] with [Decision.resyncSuggested], and are
 *    answered with a group-sync — they converge in one frame. Crucially, a burst of *stale*
 *    senders is a **backward** claim and never moves our estimate (R5), so a mass reboot
 *    cannot itself disturb anyone.
 *  - **Night mode / long heartbeat gaps.** Handled by the monotonic anchor described above.
 *
 * The guard performs no I/O and is deterministic under [io.bms.knxsecure.util.VirtualClock].
 */
class TimeSyncGuard(
    private val clock: MonotonicClock,
    private val config: Config = Config(),
    initialGroupTimestamp: Long? = null,
) {

    init {
        require(config.latencyToleranceMs in 1..8000) { "latency tolerance must be 1..8000 ms (KNX)" }
        require(config.maxForwardStepMs in 0..config.latencyToleranceMs.toLong()) {
            "maxForwardStepMs must be within [0, latencyToleranceMs]"
        }
        require(config.slewPerSecondMs >= 0.0)
        require(config.forwardBurstCapMs >= config.maxForwardStepMs)
        require(config.maxTotalForwardDriftMs <= config.latencyToleranceMs) {
            "maxTotalForwardDriftMs (${config.maxTotalForwardDriftMs}) must not exceed latencyToleranceMs " +
                "(${config.latencyToleranceMs}): forward drift beyond one tolerance would let a key-holding " +
                "attacker silence legitimate frames"
        }
        require(config.minCorroboratingSenders >= 1)
        require(config.corroborationWindowMs > 0)
        require(config.consensusSenders >= 2)
        require(config.bootstrapSamples >= 1)
        require(config.bootstrapWindowMs >= 0)
        require(config.driftDecayPpm in 0..500_000) { "driftDecayPpm must be in [0, 500000]" }
    }

    /** Where an observed timestamp came from. */
    enum class Source { TIMER_NOTIFY, DATA_FRAME }

    /** Outcome of feeding a timestamp to the guard. */
    enum class Verdict {
        /** Within tolerance of the estimate. */
        FRESH,
        /** Behind the estimate but still within tolerance; accepted. */
        ACCEPTED_AGED,
        /** Ahead of the estimate but no budget was available to correct; accepted. */
        ACCEPTED_AHEAD,
        /** A bounded forward correction was applied; accepted. */
        CORRECTED,
        /** Behind by more than the tolerance; not delivered; a resync is advisable. */
        TOO_OLD,
        /** Claimed a future time beyond policy; refused a correction, estimate unchanged. */
        REJECTED_FUTURE,
        /** Claimed a correction the drift budget cannot afford; refused, estimate unchanged. */
        REJECTED_BUDGET,
        /** Used to establish the initial anchor. */
        BOOTSTRAPPED,
        /** A bootstrap sample was collected; not yet anchored. */
        BOOTSTRAP_PENDING,
    }

    /** Machine-readable security events for monitoring / SIEM. */
    enum class Alarm {
        /** Several distinct senders are behind the estimate: it is probably inflated. */
        CLOCK_SUSPECTED_INFLATED,
        /** Forward-drift ceiling reached; further forward motion refused until resync. */
        FORWARD_DRIFT_CEILING_REACHED,
        /** A timestamp at/above the KNX high-water mark, hinting at counter exhaustion. */
        IMPLAUSIBLE_HIGH_TIMESTAMP,
        /** An observation attempted an implausible forward jump. */
        FORWARD_JUMP_REFUSED,
    }

    /** Decision returned to the caller. */
    data class Decision(
        val verdict: Verdict,
        /** True when the frame may be processed (delivered to the bus / application). */
        val deliverable: Boolean,
        /** True when the caller should proactively emit a group-sync for this peer. */
        val resyncSuggested: Boolean,
        /** True when it is safe for the caller to publish its own timestamp as authoritative. */
        val mayActAsTimeKeeper: Boolean,
        /** The guard's estimate of group time at decision time. */
        val estimateMs: Long,
        /** Difference (observation - estimate) before any correction, in ms. */
        val deltaMs: Long,
    )

    // ---- state ----------------------------------------------------------------------

    private var anchored = false
    private var baseGroupTs: Long = 0
    private var baseLocalMs: Long = 0
    private var outputHighWater: Long = 0

    // bootstrap sampling: anchor to the minimum of the first few senders so that an early
    // future-dated frame from an attacker cannot set a high anchor.
    private val bootstrapSamples = ArrayList<Pair<Long, Long>>() // (localMs, timestamp)
    private var bootstrapStartedMs: Long = 0

    private var forwardBudgetMs: Double = 0.0
    private var lastBudgetRefillMs: Long = 0
    private var totalForwardDriftMs: Long = 0

    private val pendingClaims = LinkedHashMap<Long, PendingClaim>()
    private val lastTsPerSender = HashMap<Long, Long>()
    private var highTimestampAlarmLatched = false
    private var suspectedInflated = false
    private var driftCeilingLatched = false

    private val alarmCounts = HashMap<Alarm, Long>()
    private val alarmListeners = ArrayList<(Alarm, String) -> Unit>()
    private var stats = Stats()

    init {
        if (initialGroupTimestamp != null) {
            anchor(initialGroupTimestamp, clock.nowMs())
        }
    }

    // ---- public API -----------------------------------------------------------------

    /** Registers a listener for security alarms (monitoring hook). */
    fun onAlarm(listener: (Alarm, String) -> Unit) {
        alarmListeners += listener
    }

    fun isAnchored(): Boolean = anchored

    /** Current estimate of group time. Monotonic in the local clock. */
    fun groupTimeNow(): Long = estimateAt(clock.nowMs())

    /**
     * Feeds an authenticated observation of group time.
     *
     * **Call only after the frame's MAC has verified.** The guard assumes the observation was
     * produced by a holder of the group key; its job is to survive the holder being malicious
     * or buggy.
     */
    @Synchronized
    fun observe(timestamp: Long, senderSerial: Long, source: Source): Decision {
        require(timestamp in 0..Bytes.MAX_U48) { "timestamp out of range" }
        val now = clock.nowMs()

        if (timestamp >= HIGH_TIMESTAMP && !highTimestampAlarmLatched) {
            highTimestampAlarmLatched = true
            raise(Alarm.IMPLAUSIBLE_HIGH_TIMESTAMP,
                "timestamp 0x%012x is at/above the KNX high-water mark".format(timestamp))
        }

        if (!anchored) return bootstrapSample(timestamp, senderSerial, now)

        refillBudget(now)
        val est = estimateAt(now)
        val delta = timestamp - est
        lastTsPerSender[senderSerial] = timestamp
        trimSenderMap()

        if (suspectedInflated) {
            // R6: freeze. Do not correct forward, and do not claim authority. Still deliver
            // ahead-fresh frames and reject genuinely stale ones.
            return if (delta >= -config.latencyToleranceMs) {
                Decision(Verdict.ACCEPTED_AHEAD, true, false, false, est, delta)
            } else {
                stats = stats.copy(tooOld = stats.tooOld + 1)
                Decision(Verdict.TOO_OLD, false, true, false, est, delta)
            }
        }

        return when {
            delta > config.maxForwardStepMs -> onLargeForwardClaim(timestamp, senderSerial, now, est, delta, source)
            delta > 0 -> {
                val applied = applyForward(delta, now)
                val v = if (applied > 0) Verdict.CORRECTED else Verdict.ACCEPTED_AHEAD
                Decision(v, true, false, mayActAsTimeKeeper(), est, delta)
            }
            -delta <= config.latencyToleranceMs ->
                Decision(if (delta < 0) Verdict.ACCEPTED_AGED else Verdict.FRESH, true, false, mayActAsTimeKeeper(), est, delta)
            else -> onTooOld(now, est, delta)
        }
    }

    fun observeTimerNotify(timestamp: Long, senderSerial: Long): Decision =
        observe(timestamp, senderSerial, Source.TIMER_NOTIFY)

    fun observeDataFrame(timestamp: Long, senderSerial: Long): Decision =
        observe(timestamp, senderSerial, Source.DATA_FRAME)

    /**
     * Explicit operator / provisioning resynchronisation: the only way to re-anchor after
     * [Alarm.FORWARD_DRIFT_CEILING_REACHED] or [Alarm.CLOCK_SUSPECTED_INFLATED]. It trusts the
     * supplied value completely, so it must be reachable only through an authenticated
     * management path (ETS download, device-management session), never from network input.
     */
    @Synchronized
    fun hardResync(groupTimestamp: Long, reason: String) {
        require(groupTimestamp in 0..Bytes.MAX_U48) { "timestamp out of range" }
        anchor(groupTimestamp, clock.nowMs())
        totalForwardDriftMs = 0
        forwardBudgetMs = config.forwardBurstCapMs.toDouble()
        suspectedInflated = false
        driftCeilingLatched = false
        pendingClaims.clear()
        stats = stats.copy(hardResyncs = stats.hardResyncs + 1)
    }

    fun isDriftCeilingReached(): Boolean = driftCeilingLatched
    fun isSuspectedInflated(): Boolean = suspectedInflated

    @Synchronized
    fun snapshot(): Stats = stats.copy(
        forwardDriftMs = totalForwardDriftMs,
        budgetMs = forwardBudgetMs,
        suspectedInflated = suspectedInflated,
        driftCeilingReached = driftCeilingLatched,
        anchored = anchored,
        estimatedGroupTimeMs = estimateAt(clock.nowMs()),
        alarms = alarmCounts.toMap(),
    )

    // ---- internals ------------------------------------------------------------------

    private fun bootstrapSample(timestamp: Long, senderSerial: Long, now: Long): Decision {
        if (bootstrapSamples.isEmpty()) bootstrapStartedMs = now
        bootstrapSamples += now to timestamp
        lastTsPerSender[senderSerial] = timestamp

        val samples = bootstrapSamples.size
        val windowElapsed = now - bootstrapStartedMs
        val ready = samples >= config.bootstrapSamples || windowElapsed >= config.bootstrapWindowMs

        if (!ready) {
            stats = stats.copy(bootstrapPending = stats.bootstrapPending + 1)
            return Decision(Verdict.BOOTSTRAP_PENDING, deliverable = true, resyncSuggested = false,
                mayActAsTimeKeeper = false, estimateMs = timestamp, deltaMs = 0)
        }

        // Anchor to the MINIMUM observed timestamp. Being behind is harmless (R1), so this is
        // safe even if the first frames were future-dated by an attacker; it cannot silence
        // the segment.
        val anchorTs = bootstrapSamples.minOf { it.second }
        anchor(anchorTs, now)
        bootstrapSamples.clear()
        stats = stats.copy(bootstraps = stats.bootstraps + 1)
        return Decision(Verdict.BOOTSTRAPPED, deliverable = true, resyncSuggested = false,
            mayActAsTimeKeeper = true, estimateMs = anchorTs, deltaMs = timestamp - anchorTs)
    }

    private fun anchor(groupTimestamp: Long, now: Long) {
        val target = maxOf(groupTimestamp, outputHighWater)
        anchored = true
        baseGroupTs = target
        baseLocalMs = now
        outputHighWater = target
        lastBudgetRefillMs = now
        forwardBudgetMs = config.forwardBurstCapMs.toDouble()
    }

    private fun onLargeForwardClaim(
        timestamp: Long,
        senderSerial: Long,
        now: Long,
        est: Long,
        delta: Long,
        source: Source,
    ): Decision {
        // R4: ceiling latched -> no forward motion at all. The frame is still ahead -> deliver.
        if (driftCeilingLatched) {
            stats = stats.copy(refusedBudget = stats.refusedBudget + 1)
            return Decision(Verdict.REJECTED_BUDGET, true, false, false, est, delta)
        }

        // R3: corroboration of the jump.
        val bucket = timestamp / config.corroborationBucketMs
        val claim = pendingClaims.getOrPut(bucket) { PendingClaim(timestamp, now, senderSerial) }
        claim.senders += senderSerial
        claim.lastSeenAt = now
        trimPendingClaims(now)

        val corroborated = claim.senders.size >= config.minCorroboratingSenders &&
            now - claim.firstSeenAt <= config.corroborationWindowMs

        if (!corroborated) {
            stats = stats.copy(refusedFuture = stats.refusedFuture + 1)
            raise(Alarm.FORWARD_JUMP_REFUSED,
                "${source.name} forward claim +$delta ms from sn ${"%012x".format(senderSerial)} refused " +
                    "(corroboration ${claim.senders.size}/${config.minCorroboratingSenders})")
            return Decision(Verdict.REJECTED_FUTURE, true, false, mayActAsTimeKeeper(), est, delta)
        }

        pendingClaims.remove(bucket)
        val applied = applyForward(delta, now)
        return if (applied > 0) {
            stats = stats.copy(corroboratedCorrections = stats.corroboratedCorrections + 1)
            Decision(Verdict.CORRECTED, true, false, mayActAsTimeKeeper(), est, delta)
        } else {
            stats = stats.copy(refusedBudget = stats.refusedBudget + 1)
            Decision(Verdict.REJECTED_BUDGET, true, false, mayActAsTimeKeeper(), est, delta)
        }
    }

    private fun onTooOld(now: Long, est: Long, delta: Long): Decision {
        // R6 evidence gathering. Crucial: "many senders are behind us" is only evidence of
        // *inflation* if network input actually moved us forward. With zero forward drift our
        // estimate is just tracking the local monotonic clock from the anchor, which no
        // attacker can influence — devices reporting a stale timestamp are then rebooting
        // panels, not proof that we are wrong. This is what keeps a mass power-on from
        // tripping the alarm.
        val inflatedEvidence = totalForwardDriftMs > 0 && countSendersBehind(now) >= config.consensusSenders
        if (inflatedEvidence) {
            if (!suspectedInflated) {
                suspectedInflated = true
                raise(Alarm.CLOCK_SUSPECTED_INFLATED,
                    ">=${config.consensusSenders} distinct senders are behind the estimate by more than " +
                        "${config.latencyToleranceMs} ms after ${totalForwardDriftMs} ms of applied forward drift; " +
                        "forward correction frozen pending operator resync")
            }
        }
        stats = stats.copy(tooOld = stats.tooOld + 1)
        return Decision(Verdict.TOO_OLD, false, true, false, est, delta)
    }

    /** Applies a forward correction limited by the token bucket and the drift ceiling. */
    private fun applyForward(requested: Long, now: Long): Long {
        if (requested <= 0) return 0
        val apply = minOf(
            requested,
            forwardBudgetMs.toLong(),
            (config.maxTotalForwardDriftMs - totalForwardDriftMs).coerceAtLeast(0),
        )
        if (apply <= 0) return 0
        baseGroupTs += apply
        forwardBudgetMs -= apply
        totalForwardDriftMs += apply
        outputHighWater = maxOf(outputHighWater, baseGroupTs)
        stats = stats.copy(forwardCorrections = stats.forwardCorrections + 1)
        if (totalForwardDriftMs >= config.maxTotalForwardDriftMs && !driftCeilingLatched) {
            driftCeilingLatched = true
            raise(Alarm.FORWARD_DRIFT_CEILING_REACHED,
                "forward drift ceiling ${config.maxTotalForwardDriftMs} ms reached; refusing further forward motion")
        }
        return apply
    }

    private fun refillBudget(now: Long) {
        val elapsed = (now - lastBudgetRefillMs).coerceAtLeast(0)
        if (elapsed == 0L) return
        lastBudgetRefillMs = now
        forwardBudgetMs = minOf(
            config.forwardBurstCapMs.toDouble(),
            forwardBudgetMs + config.slewPerSecondMs * (elapsed / 1000.0),
        )
        // The cumulative-drift meter also relaxes, but only at a plausible crystal-skew rate.
        // Without this, a group that legitimately runs slightly fast would accumulate drift for
        // hours and eventually latch the ceiling — a false positive. An attacker who jumps
        // ahead, by contrast, adds drift far faster than this decays it.
        if (!driftCeilingLatched && totalForwardDriftMs > 0) {
            val decay = (config.driftDecayPpm * elapsed / 1_000_000L)
            if (decay > 0) totalForwardDriftMs = (totalForwardDriftMs - decay).coerceAtLeast(0)
        }
    }

    private fun estimateAt(now: Long): Long {
        if (!anchored) return 0
        val est = baseGroupTs + (now - baseLocalMs)
        if (est > outputHighWater) outputHighWater = est
        return outputHighWater
    }

    private fun mayActAsTimeKeeper(): Boolean = anchored && !suspectedInflated && !driftCeilingLatched

    private fun countSendersBehind(now: Long): Int {
        val est = estimateAt(now)
        var n = 0
        for (ts in lastTsPerSender.values) if (est - ts > config.latencyToleranceMs) n++
        return n
    }

    private fun trimSenderMap() {
        if (lastTsPerSender.size <= MAX_TRACKED_SENDERS) return
        val it = lastTsPerSender.keys.iterator()
        while (lastTsPerSender.size > MAX_TRACKED_SENDERS && it.hasNext()) {
            it.next(); it.remove()
        }
    }

    private fun trimPendingClaims(now: Long) {
        pendingClaims.entries.removeIf { now - it.value.lastSeenAt > config.corroborationWindowMs }
        while (pendingClaims.size > MAX_PENDING_CLAIMS) pendingClaims.remove(pendingClaims.keys.iterator().next())
    }

    private fun raise(alarm: Alarm, detail: String) {
        alarmCounts[alarm] = (alarmCounts[alarm] ?: 0L) + 1
        for (l in alarmListeners) runCatching { l(alarm, detail) }
    }

    private class PendingClaim(val timestamp: Long, val firstSeenAt: Long, firstSender: Long) {
        var lastSeenAt: Long = firstSeenAt
        val senders = HashSet<Long>().apply { add(firstSender) }
    }

    data class Stats(
        val bootstraps: Long = 0,
        val bootstrapPending: Long = 0,
        val forwardCorrections: Long = 0,
        val corroboratedCorrections: Long = 0,
        val refusedFuture: Long = 0,
        val refusedBudget: Long = 0,
        val tooOld: Long = 0,
        val hardResyncs: Long = 0,
        val alarms: Map<Alarm, Long> = emptyMap(),
        val forwardDriftMs: Long = 0,
        val budgetMs: Double = 0.0,
        val suspectedInflated: Boolean = false,
        val driftCeilingReached: Boolean = false,
        val anchored: Boolean = false,
        val estimatedGroupTimeMs: Long = 0,
    )

    data class Config(
        /** Acceptance window for frames behind the estimate (KNX: 1..8000 ms). */
        val latencyToleranceMs: Int = 2000,
        /** Largest forward correction from one observation. Must be <= latencyToleranceMs. */
        val maxForwardStepMs: Long = 2000,
        /** Token-bucket refill rate for forward corrections, in ms of clock per second. */
        val slewPerSecondMs: Double = 10.0,
        /** Token-bucket capacity, i.e. the burst allowance. */
        val forwardBurstCapMs: Long = 2000,
        /** Hard cap on cumulative forward drift since the anchor / last hard resync. */
        val maxTotalForwardDriftMs: Long = 2000,
        /**
         * Rate at which accumulated forward drift relaxes, in parts per million of real time.
         * 100 ppm is a generous bound on real crystal skew (≈ 360 ms/hour), so a group that
         * genuinely runs fast is followed indefinitely instead of tripping the ceiling, while
         * an attacker who jumps ahead adds drift far faster than this can relax it.
         */
        val driftDecayPpm: Long = 100,
        /** Distinct senders required to corroborate a forward correction above the single step. */
        val minCorroboratingSenders: Int = 3,
        /** Window within which corroboration must occur. */
        val corroborationWindowMs: Long = 10_000,
        /** Bucket width used to group equivalent forward claims. */
        val corroborationBucketMs: Long = 2000,
        /** Distinct senders behind the estimate that trigger CLOCK_SUSPECTED_INFLATED. */
        val consensusSenders: Int = 3,
        /** Number of observations to collect before establishing the initial anchor. */
        val bootstrapSamples: Int = 3,
        /** Maximum time to wait for [bootstrapSamples] before anchoring anyway. */
        val bootstrapWindowMs: Long = 1000,
    ) {
        init {
            require(maxForwardStepMs <= latencyToleranceMs) { "single step must not exceed the tolerance" }
            require(corroborationBucketMs > 0) { "corroboration bucket must be positive" }
        }
    }

    companion object {
        /** KNX "high sequence number" warning threshold for 48-bit counters/timestamps. */
        const val HIGH_TIMESTAMP: Long = 0xff00_0000_0000L
        private const val MAX_TRACKED_SENDERS = 2048
        private const val MAX_PENDING_CLAIMS = 64
    }
}
