package io.bms.knxsecure.session

import io.bms.knxsecure.crypto.ReplayException
import io.bms.knxsecure.util.Bytes

/**
 * Monotonic 48-bit sequence-number tracker for a unicast tunnel session.
 *
 * KNX IP Secure requires sequence numbers to increase monotonically. Because UDP can
 * reorder or duplicate datagrams, a small window of older numbers is tolerated, but a
 * number is accepted **at most once**: replays of previously accepted frames are rejected.
 *
 * The tracker is fed only after the frame's MAC has verified, so an attacker without the
 * session key cannot influence it at all.
 *
 * @param window number of sequence numbers behind the high-water mark that may still be
 *        accepted (out-of-order delivery). 0 means strictly increasing.
 * @param maxForwardJump largest tolerated single jump; larger jumps are treated as an
 *        anomaly (logged by the caller) because they normally indicate lost traffic or a
 *        protocol bug. They are still accepted once, to avoid dropping legitimate traffic.
 */
class SequenceTracker(
    private val window: Int = 64,
    private val maxForwardJump: Long = 1L shl 20,
) {
    init {
        require(window in 0..4096) { "window out of range" }
        require(window <= 64) { "backing bitmap holds at most 64 entries" }
    }

    private var highest: Long = -1
    private var seenBitmap: Long = 0
    private var acceptedCount: Long = 0
    private var rejectedReplays: Long = 0
    private var rejectedOld: Long = 0
    private var forwardAnomalies: Long = 0

    /** Result of a check. */
    enum class Result { ACCEPTED, DUPLICATE, TOO_OLD, FORWARD_ANOMALY }

    @Synchronized
    fun offer(sequence: Long): Result {
        require(sequence in 0..Bytes.MAX_U48) { "sequence out of range" }
        if (highest < 0) {
            highest = sequence
            seenBitmap = 1L
            acceptedCount++
            return Result.ACCEPTED
        }

        when {
            sequence > highest -> {
                val jump = sequence - highest
                val anomaly = jump > maxForwardJump
                shiftForward(jump)
                highest = sequence
                seenBitmap = seenBitmap or 1L
                acceptedCount++
                if (anomaly) {
                    forwardAnomalies++
                    return Result.FORWARD_ANOMALY
                }
                return Result.ACCEPTED
            }
            else -> {
                val behind = highest - sequence
                if (behind >= window + 1 || behind >= 64) {
                    rejectedOld++
                    return Result.TOO_OLD
                }
                val bit = 1L shl behind.toInt()
                if (seenBitmap and bit != 0L) {
                    rejectedReplays++
                    return Result.DUPLICATE
                }
                seenBitmap = seenBitmap or bit
                acceptedCount++
                return Result.ACCEPTED
            }
        }
    }

    /** Like [offer] but throws on anything other than acceptance. */
    @Synchronized
    fun requireAccept(sequence: Long, context: String = "session") {
        when (val r = offer(sequence)) {
            Result.ACCEPTED, Result.FORWARD_ANOMALY -> Unit
            Result.DUPLICATE -> throw ReplayException("$context: duplicate sequence $sequence")
            Result.TOO_OLD -> throw ReplayException("$context: replayed/expired sequence $sequence (highest=$highest)")
        }
    }

    private fun shiftForward(jump: Long) {
        seenBitmap = if (jump >= 64) 0L else seenBitmap shl jump.toInt()
    }

    @Synchronized
    fun highestAccepted(): Long = highest

    @Synchronized
    fun nextExpected(): Long = if (highest < 0) 0 else highest + 1

    @Synchronized
    fun stats(): Stats = Stats(highest, acceptedCount, rejectedReplays, rejectedOld, forwardAnomalies)

    data class Stats(
        val highest: Long,
        val accepted: Long,
        val rejectedReplays: Long,
        val rejectedOld: Long,
        val forwardAnomalies: Long,
    )
}
