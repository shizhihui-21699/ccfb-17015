package knxsec

/**
 * 隧道网关整体：单播会话层（SessionServer）+ 组播路由接收（时间同步 + 重放窗口）。
 * 网关本身不是时间主节点，它像普通设备一样通过 TimingSynchronizer 跟随
 * 受信的时间通知 —— 伪造通知攻击的第一落点就是这里。
 */
class Gateway(
    val endpoint: Endpoint,
    val bus: LoopbackBus,
    password: String,
    private val backboneKey: ByteArray,
    val now: () -> Long,
    maxSessions: Int = 64,
    /** 组播重放窗口（毫秒单位），按最大心跳间隔 × 2 配置 */
    val mcastWindowMs: Long = 130_000L,
) {
    val server = SessionServer(password, maxSessions, now, { to, data -> bus.send(endpoint, to, data) })
    val timing = TimingSynchronizer(backboneKey, now)

    private val mcastWindows = LinkedHashMap<Int, ReplayWindow>()

    var onMcastData: ((senderId: Int, inner: Frame) -> Unit)? = null

    val mcastStats = McastStats()

    class McastStats {
        var accepted = 0
        var authFailures = 0
        var replayDropped = 0
        var futureDropped = 0
        var notSyncedDropped = 0
    }

    fun handle(from: Endpoint, data: ByteArray) {
        val frame = Frame.decode(data) ?: return
        when (frame.serviceType) {
            ServiceType.MCAST_WRAPPER -> onMcast(frame)
            ServiceType.TIMER_NOTIFY -> onTimingNotify(frame)
            else -> server.handle(from, frame)
        }
    }

    private fun onTimingNotify(frame: Frame) {
        val (senderId, timer, tag) = TimingMaster.parseNotify(frame) ?: return
        timing.onNotify(senderId, timer, tag)
    }

    private fun onMcast(frame: Frame) {
        val (senderId, seq, inner) = McastWrapper.unwrap(backboneKey, frame) ?: run {
            mcastStats.authFailures++
            return
        }
        val est = timing.estimate()
        if (est < 0) {
            mcastStats.notSyncedDropped++
            return
        }
        if (seq > est + FUTURE_SLACK_MS) {
            mcastStats.futureDropped++
            return
        }
        val window = mcastWindows.getOrPut(senderId) { ReplayWindow(mcastWindowMs) }
        if (!window.accept(seq, est, FUTURE_SLACK_MS)) {
            mcastStats.replayDropped++
            return
        }
        mcastStats.accepted++
        onMcastData?.invoke(senderId, inner)
    }

    fun sweep() = server.sweep()

    companion object {
        /** 合法发送方时钟相对本地估计的最大超前量 */
        const val FUTURE_SLACK_MS = 2_000L
    }
}
