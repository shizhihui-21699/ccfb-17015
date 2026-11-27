package knxsec

/** 网络端点。 */
data class Endpoint(val host: String, val port: Int)

/**
 * 进程内回环总线：同步投递，测试可注入丢弃/篡改规则，攻击者可从任意伪造源地址发包。
 * 真实部署时把 send/receive 换成 DatagramChannel 即可，协议层不变。
 */
class LoopbackBus {
    private val handlers = LinkedHashMap<Endpoint, (Endpoint, ByteArray) -> Unit>()

    /** 返回 true 表示丢弃该报文（模拟丢包/链路故障）。 */
    @Volatile
    var dropRule: ((from: Endpoint, to: Endpoint, data: ByteArray) -> Boolean)? = null

    var delivered = 0L
        private set

    fun register(ep: Endpoint, handler: (Endpoint, ByteArray) -> Unit) {
        handlers[ep] = handler
    }

    fun unregister(ep: Endpoint) {
        handlers.remove(ep)
    }

    fun send(from: Endpoint, to: Endpoint, data: ByteArray) {
        if (to == MULTICAST) {
            // 组播：投递给除发送者外的所有节点
            for ((ep, h) in handlers.toMap()) {
                if (ep == from) continue
                if (dropRule?.invoke(from, ep, data) == true) continue
                delivered++
                h(from, data)
            }
        } else {
            val h = handlers[to] ?: return
            if (dropRule?.invoke(from, to, data) == true) return
            delivered++
            h(from, data)
        }
    }

    companion object {
        /** KNXnet/IP 标准组播地址 */
        val MULTICAST = Endpoint("224.0.23.12", 3671)
    }
}
