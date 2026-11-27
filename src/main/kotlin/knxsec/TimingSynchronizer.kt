package knxsec

/**
 * 组播路由模式下的时间计数同步器 —— 防御伪造 TIMER_NOTIFY 的核心。
 *
 * 攻击场景：攻击者伪造时间通知把整个网段的时间计数往前推，
 * 让合法设备发出的报文序号全部落在重放窗口之外，被当成过期帧丢弃（DoS）；
 * 或者往回推，让已收过的旧帧重新落入窗口（重放）。
 *
 * 防御分三层：
 * 1. TIMER_NOTIFY 本身携带主干密钥的 CCM 标签，无密钥伪造直接丢弃；
 * 2. 即使密钥泄露（或内部人作恶），本地时间估计也只能按墙钟速率前进：
 *    单次通知允许的前进量 = 距上次的墙钟间隔 × (1+漂移容差) + 固定抖动余量。
 *    超出则拒绝并计违规，本地估计不受任何影响 —— 合法报文永远不会被"推过期"；
 * 3. 回推（timer 明显小于当前基准）同样拒绝，防止旧帧复活。
 *
 * 合法场景不受误伤：
 * - 主节点正常周期广播：间隔 ≈ 广播周期，远在容差之内；
 * - 夜间节能拉长广播间隔：容差随墙钟间隔线性放大，间隔越长允许的前进量越大；
 * - 首次同步（设备刚上电）：无基准，直接采纳（此时还没有可保护的窗口状态）。
 */
class TimingSynchronizer(
    private val backboneKey: ByteArray,
    private val now: () -> Long,
    private val maxDriftPpm: Long = 1_000,      // 允许的时钟漂移（0.1%）
    private val jitterSlackMs: Long = 2_000,    // 固定抖动/量化余量
) {
    var timerBase = -1L
        private set
    private var baseWall = -1L

    /** 标签合法但跃迁超限被拒的次数（安全审计指标）。 */
    var violations = 0
        private set

    /** 标签非法被直接丢弃的次数。 */
    var macFailures = 0
        private set

    /** 当前时间计数估计；未同步返回 -1。 */
    fun estimate(): Long =
        if (timerBase < 0) -1L else timerBase + (now() - baseWall)

    val synced: Boolean get() = timerBase >= 0

    /** @return true 表示采纳（含正常小抖动重复帧） */
    fun onNotify(senderId: Int, timerValue: Long, tag: ByteArray): Boolean {
        if (!TimingMaster.verify(backboneKey, senderId, timerValue, tag)) {
            macFailures++
            return false
        }
        if (timerBase < 0) {
            accept(timerValue)
            return true
        }
        val elapsed = now() - baseWall
        val maxAdvance = elapsed + elapsed * maxDriftPpm / 1_000_000 + jitterSlackMs
        val delta = timerValue - timerBase
        if (delta < -jitterSlackMs || delta > maxAdvance) {
            violations++
            return false
        }
        if (timerValue > timerBase) accept(timerValue)
        // 窗口内的轻微乱序/重复：保持原基准，视为正常
        return true
    }

    private fun accept(v: Long) {
        timerBase = v
        baseWall = now()
    }
}
