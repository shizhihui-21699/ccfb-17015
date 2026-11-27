package knxsec

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class SecureSessionTest {

    companion object {
        @BeforeAll
        @JvmStatic
        fun speedUpKdf() {
            Crypto.pbkdf2Iterations = 512 // 测试加速；生产 65536
        }
    }

    private lateinit var clock: ManualClock
    private lateinit var bus: LoopbackBus
    private lateinit var gateway: Gateway
    private lateinit var master: TimingMasterNode
    private lateinit var attacker: Attacker
    private val gwEp = Endpoint("192.168.1.1", 3671)
    private val password = "test-pw"
    private val backboneKey = ByteArray(16) { (it * 7).toByte() }
    private val received = mutableListOf<Pair<Int, Frame>>()
    private val mcastReceived = mutableListOf<Pair<Int, Frame>>()

    @BeforeEach
    fun setup() {
        clock = ManualClock()
        bus = LoopbackBus()
        gateway = Gateway(gwEp, bus, password, backboneKey, clock::now, maxSessions = 64)
        bus.register(gwEp, gateway::handle)
        master = TimingMasterNode(1, backboneKey, bus, Endpoint("192.168.1.2", 3671), clock::now)
        bus.register(Endpoint("192.168.1.2", 3671)) { _, _ -> }
        attacker = Attacker(bus, Endpoint("10.66.6.6", 6666))
        received.clear()
        mcastReceived.clear()
        gateway.server.onData = { sid, _, inner -> received += sid to inner }
        gateway.onMcastData = { sid, inner -> mcastReceived += sid to inner }
    }

    private var nextDeviceIp = 10

    private fun device(
        pw: String = password,
        heartbeatMs: Long = 20_000,
        id: Int = nextDeviceIp,
    ): SimDevice {
        val d = SimDevice(id, Endpoint("192.168.1.${nextDeviceIp++}", 3671), bus, gwEp, pw, backboneKey, heartbeatMs, clock::now)
        bus.register(d.endpoint, d::handle)
        return d
    }

    // ---------- 正常路径 ----------

    @Test
    fun `握手与加密数据交换`() {
        val d = device()
        assertTrue(d.connect())
        assertEquals(1, gateway.server.sessionCount)

        d.sendData("hello".toByteArray())
        assertEquals(1, received.size)
        assertEquals(ServiceType.TUNNELLING_REQUEST, received[0].second.serviceType)
        assertEquals("hello", String(received[0].second.body))

        // 网关 -> 设备方向
        assertTrue(gateway.server.sendData(d.sessionId, Frame(ServiceType.TUNNELLING_REQUEST, "ack".toByteArray())))
        assertEquals(1, d.receivedData.size)
    }

    @Test
    fun `错误口令被拒绝且不分配会话`() {
        val d = device(pw = "wrong-pw")
        assertFalse(d.connect())
        assertEquals(1, d.lastStatus)
        assertEquals(0, gateway.server.sessionCount)
        assertEquals(1, gateway.server.stats.authFailures)
    }

    // ---------- 单播重放 ----------

    @Test
    fun `重放的单播封装帧被丢弃`() {
        val d = device()
        d.connect()
        // 录制一帧合法数据
        var captured: ByteArray? = null
        val orig = bus.dropRule
        bus.dropRule = { _, _, _ -> false } // 占位，确保可恢复
        // 直接拦截总线：包一层 handler 抓取设备发出的帧
        bus.unregister(d.endpoint)
        val spy = object {
            var lastSent: ByteArray? = null
        }
        // 用 dropRule 抓包：观察从设备发出的帧
        bus.dropRule = { from, _, data ->
            if (from == d.endpoint) spy.lastSent = data
            false
        }
        d.sendData("cmd".toByteArray())
        captured = spy.lastSent
        bus.dropRule = orig
        bus.register(d.endpoint, d::handle)

        assertNotNull(captured)
        assertEquals(1, received.size)
        // 攻击者伪造设备源地址重放（从真实地址重放则会被会话-地址绑定拦截）
        bus.send(d.endpoint, gwEp, captured!!)
        assertEquals(1, received.size) // 没有重复投递
        assertEquals(1, gateway.server.stats.replaysDropped)
    }

    // ---------- 伪造时间通知 ----------

    @Test
    fun `无密钥伪造时间通知被标签校验丢弃`() {
        master.broadcast()
        val est = gateway.timing.estimate()
        attacker.forgeTimingNotify(clock.now() + 3_600_000, senderId = 1, key = null)
        assertEquals(1, gateway.timing.macFailures)
        assertEquals(est, gateway.timing.estimate())
    }

    @Test
    fun `密钥泄露下前推时间计数被钳制且合法帧不误判`() {
        master.broadcast() // t0 同步
        clock.advance(1_000)
        master.broadcast()

        // 攻击者拿着泄露的主干密钥，把计数往前推 1 小时
        attacker.forgeTimingNotify(clock.now() + 3_600_000, senderId = 1, key = backboneKey)
        assertEquals(1, gateway.timing.violations)
        // 估计值只允许按墙钟前进（约 0，因为墙钟没动）
        assertTrue(gateway.timing.estimate() - clock.now() < 5_000)

        // 合法设备照常发组播，必须被接受 —— 不能被攻击者"推过期"
        val d = device()
        clock.advance(1_000)
        master.broadcast()
        assertTrue(d.sendMulticast("event".toByteArray()))
        assertEquals(1, gateway.mcastStats.accepted)
    }

    @Test
    fun `回推时间计数同样被拒绝`() {
        master.broadcast()
        clock.advance(5_000)
        master.broadcast()
        attacker.forgeTimingNotify(clock.now() - 60_000, senderId = 1, key = backboneKey)
        assertEquals(1, gateway.timing.violations)
    }

    @Test
    fun `夜间拉长的时间广播间隔不误判`() {
        master.broadcast()
        // 夜间节能：主节点 60s 才广播一次
        clock.advance(60_000)
        master.broadcast()
        assertEquals(0, gateway.timing.violations)
        assertTrue(gateway.timing.synced)
    }

    // ---------- 组播重放窗口 ----------

    @Test
    fun `组播乱序帧在窗口内接受而重放与过旧帧拒绝`() {
        master.broadcast()
        val d = device(id = 42)
        // 让设备与网关都完成同步
        clock.advance(1_000)
        master.broadcast()

        // 手工构造三条乱序帧：seq = est, est+1, 然后重放 est
        val est = gateway.timing.estimate()
        val mk = { seq: Long ->
            McastWrapper.wrap(backboneKey, 42, seq, Frame(ServiceType.ROUTING_INDICATION, "x".toByteArray())).encode()
        }
        bus.send(d.endpoint, LoopbackBus.MULTICAST, mk(est))
        bus.send(d.endpoint, LoopbackBus.MULTICAST, mk(est + 2))
        bus.send(d.endpoint, LoopbackBus.MULTICAST, mk(est + 1)) // 乱序但在窗口内
        assertEquals(3, gateway.mcastStats.accepted)

        bus.send(d.endpoint, LoopbackBus.MULTICAST, mk(est))     // 重放
        assertEquals(1, gateway.mcastStats.replayDropped)

        bus.send(d.endpoint, LoopbackBus.MULTICAST, mk(est - 200_000)) // 窗口之外
        assertEquals(2, gateway.mcastStats.replayDropped)

        bus.send(d.endpoint, LoopbackBus.MULTICAST, mk(est + 3_600_000)) // 未来帧
        assertEquals(1, gateway.mcastStats.futureDropped)
    }

    @Test
    fun `无密钥伪造组播数据帧被标签校验丢弃`() {
        master.broadcast()
        attacker.forgeMcast(gwEp, senderId = 7, timerSeq = clock.now(), payload = "evil".toByteArray())
        assertEquals(1, gateway.mcastStats.authFailures)
        assertEquals(0, mcastReceived.size)
    }

    // ---------- 会话耗尽 ----------

    @Test
    fun `会话泛洪不分配状态且合法设备可建链`() {
        attacker.sessionFlood(gwEp, 5_000)
        assertEquals(0, gateway.server.sessionCount)          // 无状态 cookie：零分配
        assertTrue(gateway.server.stats.rateLimited > 0)      // 限流生效

        clock.advance(1_000) // 全局桶补充
        val d = device()
        assertTrue(d.connect())
        assertEquals(1, gateway.server.sessionCount)
    }

    @Test
    fun `会话表满时拒绝新会话但不影响已建立会话`() {
        val small = Gateway(gwEp, bus, password, backboneKey, clock::now, maxSessions = 2)
        small.server.onData = { sid, _, inner -> received += sid to inner }
        bus.unregister(gwEp)
        bus.register(gwEp, small::handle)
        val a = device(); val b = device(); val c = device()
        assertTrue(a.connect())
        assertTrue(b.connect())
        assertFalse(c.connect())
        assertEquals(2, c.lastStatus) // BUSY
        // 已建立会话照常收发
        a.sendData("still-alive".toByteArray())
        assertEquals(1, received.size)
    }

    @Test
    fun `录制合法认证报文重放不能换到第二个会话`() {
        val d = device()
        // 抓取设备发出的认证帧
        var authFrame: ByteArray? = null
        bus.dropRule = { from, _, data ->
            if (from == d.endpoint && Frame.decode(data)?.serviceType == ServiceType.SESSION_AUTHENTICATE) {
                authFrame = data
            }
            false
        }
        d.connect()
        bus.dropRule = null
        assertNotNull(authFrame)
        assertEquals(1, gateway.server.sessionCount)

        attacker.replay(gwEp, authFrame!!)
        assertEquals(1, gateway.server.sessionCount) // cookie 已消费，重放无效
        assertEquals(1, gateway.server.stats.cookieRejected)
    }

    // ---------- 合法突发场景 ----------

    @Test
    fun `整楼 100 个面板同时上电全部建链成功`() {
        val big = Gateway(gwEp, bus, password, backboneKey, clock::now, maxSessions = 128)
        bus.unregister(gwEp)
        bus.register(gwEp, big::handle)
        val devices = (1..100).map { device(id = it) }
        devices.forEach { assertTrue(it.connect(), "设备建链失败") }
        assertEquals(100, big.server.sessionCount)
    }

    @Test
    fun `夜间模式长心跳会话存活且静默超时后清理`() {
        val night = device(heartbeatMs = 60_000)
        night.connect()
        val sid = night.sessionId

        repeat(10) { // 10 分钟，每分钟一次心跳
            clock.advance(60_000)
            night.tick()
            gateway.sweep()
        }
        assertNotNull(gateway.server.session(sid))

        clock.advance(160_000) // 心跳停止，超过 150s 超时
        gateway.sweep()
        assertNull(gateway.server.session(sid))
        assertEquals(1, gateway.server.stats.expired)
    }

    @Test
    fun `心跳间隔内会话不因空闲被误杀`() {
        val d = device(heartbeatMs = 20_000)
        d.connect()
        // 每次心跳刚到就推进，模拟正常在线设备
        repeat(20) {
            clock.advance(20_000)
            d.tick()
            gateway.sweep()
        }
        assertEquals(1, gateway.server.sessionCount)
        assertEquals(0, gateway.server.stats.expired)
    }
}
