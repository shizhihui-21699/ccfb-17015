package knxsec

/** 攻击模拟器：从任意（可伪造的）源地址向总线注入报文。 */
class Attacker(val bus: LoopbackBus, val endpoint: Endpoint) {

    /**
     * 伪造时间通知。key 为 null 表示无密钥乱造标签（被 CCM 直接丢弃）；
     * 传入真实主干密钥则模拟密钥泄露/内部人场景（由跃迁约束兜底）。
     */
    fun forgeTimingNotify(timerValue: Long, senderId: Int, key: ByteArray? = null) {
        val tag = key?.let { TimingMaster.tag(it, senderId, timerValue) } ?: ByteArray(Crypto.TAG_LEN) { 0x41 }
        bus.send(
            endpoint,
            LoopbackBus.MULTICAST,
            Frame(ServiceType.TIMER_NOTIFY, be16(senderId) + be48(timerValue) + tag).encode()
        )
    }

    /** 会话耗尽泛洪：从大量伪造源 IP 发送 SESSION_REQUEST。 */
    fun sessionFlood(gateway: Endpoint, count: Int, baseOctet: Int = 200) {
        repeat(count) { i ->
            val fakePub = ByteArray(32) { (it * 31 + i).toByte() }
            val fakeFrom = Endpoint("10.${baseOctet}.${i / 250}.${i % 250}", 40000 + i % 20000)
            bus.send(fakeFrom, gateway, Msg.sessionRequest(fakePub).encode())
        }
    }

    /** 重放录制到的报文。 */
    fun replay(target: Endpoint, captured: ByteArray) {
        bus.send(endpoint, target, captured)
    }

    /** 伪造组播数据帧（无主干密钥，标签必然无效）。 */
    fun forgeMcast(target: Endpoint, senderId: Int, timerSeq: Long, payload: ByteArray) {
        val body = be16(senderId) + be48(timerSeq) + payload + ByteArray(Crypto.TAG_LEN) { 0x42 }
        bus.send(endpoint, target, Frame(ServiceType.MCAST_WRAPPER, body).encode())
    }
}
