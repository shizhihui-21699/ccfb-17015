package io.bms.knxsecure.util

/**
 * Monotonic millisecond clock abstraction.
 *
 * Every time-sensitive security decision in this project goes through this interface.
 * Tests inject a [VirtualClock] so that keep-alive intervals, session TTLs, multicast
 * timestamp budgets and clock-slew behaviour are deterministic and can be accelerated.
 *
 * The clock is deliberately *monotonic* and unrelated to wall-clock time: KNX group
 * timestamps are an arbitrary time base agreed within the multicast group, and using a
 * wall clock would make every node vulnerable to NTP steps.
 */
fun interface MonotonicClock {
    /** Milliseconds from an arbitrary but monotonically non-decreasing origin. */
    fun nowMs(): Long
}

/** Production clock based on [System.nanoTime]. */
object SystemMonotonicClock : MonotonicClock {
    override fun nowMs(): Long = System.nanoTime() / 1_000_000L
}

/**
 * Deterministic scheduler used by the in-memory simulator and the test-suite.
 *
 * Tasks are executed in due-time order when the clock is advanced. Ties are broken by
 * scheduling order (stable), which keeps simulations reproducible regardless of JVM
 * iteration order.
 */
class VirtualClock(startMs: Long = 0L) : MonotonicClock {

    private var current = startMs
    private var sequence = 0L
    private val tasks = java.util.PriorityQueue<ScheduledTask>(
        compareBy<ScheduledTask>({ it.dueMs }, { it.order })
    )

    override fun nowMs(): Long = current

    @Synchronized
    fun schedule(delayMs: Long, action: () -> Unit): VirtualTask {
        require(delayMs >= 0) { "negative delay" }
        val t = ScheduledTask(current + delayMs, sequence++, action)
        tasks += t
        return VirtualTask(t)
    }

    /**
     * Advances the clock by [deltaMs], running every task that becomes due, in order.
     * Tasks scheduled by tasks are honoured within the same advance when they fall inside it.
     */
    @Synchronized
    fun advanceBy(deltaMs: Long) {
        require(deltaMs >= 0) { "cannot move a monotonic clock backwards" }
        advanceTo(current + deltaMs)
    }

    @Synchronized
    fun advanceTo(targetMs: Long) {
        require(targetMs >= current) { "cannot move a monotonic clock backwards" }
        while (true) {
            val next = tasks.peek() ?: break
            if (next.dueMs > targetMs) break
            tasks.poll()
            if (next.cancelled) continue
            current = maxOf(current, next.dueMs)
            next.action()
        }
        current = targetMs
    }

    /** Runs a single due task without moving the clock (used to test tight event loops). */
    @Synchronized
    fun runNextDue(): Boolean {
        val next = tasks.poll() ?: return false
        if (next.cancelled) return true
        current = maxOf(current, next.dueMs)
        next.action()
        return true
    }

    @Synchronized
    fun pendingTasks(): Int = tasks.count { !it.cancelled }

    class VirtualTask internal constructor(private val task: ScheduledTask) {
        fun cancel() { task.cancelled = true }
    }

    internal class ScheduledTask(
        val dueMs: Long,
        val order: Long,
        val action: () -> Unit,
    ) {
        @Volatile var cancelled: Boolean = false
    }
}
