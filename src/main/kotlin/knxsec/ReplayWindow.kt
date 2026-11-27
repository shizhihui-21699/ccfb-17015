package knxsec

import java.util.BitSet

/**
 * 滑动重放窗口（用于组播 48 位时间序号）。
 *
 * 合法组播报文允许乱序和迟到（楼里大量面板同时上电、夜间心跳拉长都是常态），
 * 所以不能用"严格大于上一帧"的单播规则，而是维护一个窗口：
 * - 序号超过当前时间估计 + futureSlack → 未来帧，拒绝
 * - 序号落后最高已收帧超过 windowSize → 过旧，拒绝
 * - 窗口内已见过的序号 → 重放，拒绝
 */
class ReplayWindow(val windowSize: Long) {
    var highest = -1L
        private set
    private var bits = BitSet()

    /** @param estimate 当前时间计数估计（未同步时传 -1，则不做未来检查） */
    fun accept(seq: Long, estimate: Long, futureSlack: Long): Boolean {
        if (estimate >= 0 && seq > estimate + futureSlack) return false
        if (highest < 0) {
            highest = seq
            bits.set(0)
            return true
        }
        if (seq > highest) {
            val shift = (seq - highest).coerceAtMost(windowSize).toInt()
            val shifted = BitSet()
            var i = bits.nextSetBit(0)
            while (i >= 0) {
                if (i + shift < windowSize) shifted.set(i + shift)
                i = bits.nextSetBit(i + 1)
            }
            shifted.set(0)
            bits = shifted
            highest = seq
            return true
        }
        val idx = highest - seq
        if (idx >= windowSize) return false
        if (bits.get(idx.toInt())) return false
        bits.set(idx.toInt())
        return true
    }
}
