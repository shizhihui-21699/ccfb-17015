package knxsec

/**
 * 端到端演示：正常场景 + 攻击场景，全部用虚拟时钟确定性运行。
 * 运行：gradle run
 */
fun main() {
    Crypto.pbkdf2Iterations = 4096 // 演示加速；生产保持 65536

    val clock = ManualClock()
    val now = clock::now
    val bus = LoopbackBus()
    val gwEp = Endpoint("192.168.1.1", 3671)
    val password = "building-A-tunnel-pw"
    val backboneKey = ByteArray(16) { it.toByte() }

    val gateway = Gateway(gwEp, bus, password, backboneKey, now, maxSessions = 64)
    bus.register(gwEp, gateway::handle)
    val master = TimingMasterNode(1, backboneKey, bus, Endpoint("192.168.1.2", 3671), now)
    bus.register(Endpoint("192.168.1.2", 3671)) { _, _ -> }
    val attacker = Attacker(bus, Endpoint("10.66.6.6", 6666))

    val receivedAtGateway = mutableListOf<Pair<Int, Frame>>()
    gateway.server.onData = { sid, _, inner -> receivedAtGateway += sid to inner }
    val mcastAtGateway = mutableListOf<Pair<Int, Frame>>()
    gateway.onMcastData = { sid, inner -> mcastAtGateway += sid to inner }

    fun device(i: Int, heartbeatMs: Long = 20_000) =
        SimDevice(i, Endpoint("192.168.1.${10 + i}", 3671), bus, gwEp, password, backboneKey, heartbeatMs, now)
            .also { bus.register(it.endpoint, it::handle) }

    println("== 场景 1：10 个面板正常建会话、收发数据 ==")
    master.broadcast() // 时间同步
    val devices = (1..10).map { device(it) }
    devices.forEach { it.connect() }
    println("  建链成功: ${devices.count { it.established }}/10, 网关会话数=${gateway.server.sessionCount}")
    devices.forEach { it.sendData("switch-on".toByteArray()) }
    println("  网关收到隧道数据帧: ${receivedAtGateway.size}/10")

    println("== 场景 2：组播路由 + 伪造时间通知攻击 ==")
    clock.advance(1_000); master.broadcast()
    devices[0].sendMulticast("panel-event".toByteArray())
    println("  合法组播帧被接受: ${gateway.mcastStats.accepted == 1}")

    // 攻击 2a：无密钥伪造 —— CCM 标签直接打回
    attacker.forgeTimingNotify(clock.now() + 3_600_000, senderId = 1, key = null)
    println("  无密钥伪造: 网关端 macFailures=${gateway.timing.macFailures} (标签校验丢弃)")
    println("  网关估计值未被推动: ${gateway.timing.estimate() - clock.now() < 10_000}")

    // 攻击 2b：主干密钥泄露，伪造合法标签把计数往前推 1 小时
    val estBefore = gateway.timing.estimate()
    attacker.forgeTimingNotify(clock.now() + 3_600_000, senderId = 1, key = backboneKey)
    val estAfter = gateway.timing.estimate()
    println("  密钥泄露前推 +1h: 违规计数=${gateway.timing.violations}, 估计值漂移=${estAfter - estBefore}ms (应≈0)")
    clock.advance(1_000); master.broadcast()
    devices[1].sendMulticast("panel-event-2".toByteArray())
    println("  攻击后合法组播仍被接受: ${gateway.mcastStats.accepted == 2} (合法流量未被误判过期)")

    println("== 场景 3：会话耗尽泛洪 ==")
    val before = gateway.server.sessionCount
    attacker.sessionFlood(gwEp, 5_000)
    println("  5000 个伪造请求后: 会话数=${gateway.server.sessionCount} (应=$before), 被限流=${gateway.server.stats.rateLimited}")
    val late = device(99)
    clock.advance(1_000) // 等全局桶补充
    println("  合法设备随后建链: ${late.connect()}")

    println("== 场景 4：夜间节能模式（心跳 60s）==")
    val night = device(50, heartbeatMs = 60_000)
    night.connect()
    repeat(10) { // 模拟 10 分钟，每分钟一次心跳
        clock.advance(60_000)
        night.tick()
        gateway.sweep()
    }
    println("  10 分钟长心跳后会话存活: ${gateway.server.session(night.sessionId) != null}")
    clock.advance(160_000) // 心跳停止，超过 150s 超时
    gateway.sweep()
    println("  心跳停止 160s 后会话被清理: ${gateway.server.session(night.sessionId) == null}")

    println("== 场景 5：重放与伪造 ==")
    devices[2].connect() // 场景 4 推进了时钟，原会话已过期，重新建链
    // 录制一帧合法单播数据并重放
    var captured: ByteArray? = null
    bus.dropRule = { from, _, data ->
        if (from == devices[2].endpoint && Frame.decode(data)?.serviceType == ServiceType.SECURE_WRAPPER) captured = data
        false
    }
    devices[2].sendData("replay-me".toByteArray())
    bus.dropRule = null
    val before2 = receivedAtGateway.size
    bus.send(devices[2].endpoint, gwEp, captured!!) // 攻击者伪造设备源地址重放
    println("  重放合法帧: 网关未重复投递=${receivedAtGateway.size == before2}, 重放丢弃计数=${gateway.server.stats.replaysDropped}")
    // 无密钥伪造组播数据帧
    attacker.forgeMcast(gwEp, senderId = 7, timerSeq = clock.now(), payload = "evil".toByteArray())
    println("  伪造组播帧: 认证失败丢弃=${gateway.mcastStats.authFailures == 1}")
    val s = gateway.server.stats
    println("完成。网关统计: 请求=${s.requests} 限流=${s.rateLimited} 建链=${s.established} " +
        "认证失败=${s.authFailures} cookie拒绝=${s.cookieRejected} 重放丢弃=${s.replaysDropped} 过期清理=${s.expired}")
}
