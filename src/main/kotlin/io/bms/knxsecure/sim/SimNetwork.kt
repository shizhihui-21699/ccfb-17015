package io.bms.knxsecure.sim

import io.bms.knxsecure.client.SecureTunnelClient
import io.bms.knxsecure.client.TunnelPackets
import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.Pbkdf2
import io.bms.knxsecure.util.Bytes
import io.bms.knxsecure.util.VirtualClock
import io.bms.knxsecure.wire.Endpoint
import io.bms.knxsecure.wire.SecureFrames
import io.bms.knxsecure.wire.SessionStatus

/**
 * One in-process "wire" shared by every simulated device.
 *
 * Unicast queues keep the sender, because the tunnel gateway must verify that a datagram's
 * source matches the session's endpoint — a property the tests and demo exercise directly.
 */
class SimNetwork(val clock: VirtualClock) {
    private val unicast = HashMap<Endpoint, ArrayDeque<Datagram>>()
    private val multicast = ArrayList<Datagram>()
    private val bus = ArrayList<ByteArray>()

    data class Datagram(val from: Endpoint, val frame: ByteArray)

    fun sendUnicast(from: Endpoint, to: Endpoint, frame: ByteArray) {
        unicast.getOrPut(to) { ArrayDeque() }.addLast(Datagram(from, frame))
    }

    fun drainUnicast(to: Endpoint): List<Datagram> {
        val q = unicast[to] ?: return emptyList()
        val out = q.toList()
        q.clear()
        return out
    }

    fun pendingUnicast(to: Endpoint): Int = unicast[to]?.size ?: 0

    fun broadcastMulticast(frame: ByteArray, from: Endpoint = Endpoint.of("239.0.0.1", 3671)) {
        multicast += Datagram(from, frame)
    }

    fun drainMulticast(): List<Datagram> {
        val out = multicast.toList()
        multicast.clear()
        return out
    }

    fun publishToBus(packet: ByteArray) {
        bus += packet
    }

    fun busTraffic(): List<ByteArray> = bus.toList()
    fun clearBus() = bus.clear()
}

/** Password material for a whole simulated installation. */
object SimPasswords {
    const val USER = "installer-pw"
    const val DEVICE = "device-code-1234"
    val userKey: ByteArray get() = Pbkdf2.userKey(USER)
    val deviceKey: ByteArray get() = Pbkdf2.deviceAuthKey(DEVICE)
    val groupKey: AesKey get() = AesKey.of(Bytes.unhex("00112233445566778899aabbccddeeff"))
}

/**
 * A simulated KNX panel using the real secure tunnel client.
 *
 * Panels behave exactly like devices on the wire; the only thing simulated is transport.
 */
class SimPanel(
    val name: String,
    val individualAddress: Int,
    val endpoint: Endpoint,
    val serialNumber: Long,
    private val net: SimNetwork,
    val clock: VirtualClock,
    password: String = SimPasswords.USER,
    devicePassword: String = SimPasswords.DEVICE,
    userId: Int = 1,
) {
    private val client = SecureTunnelClient(
        endpoint = endpoint,
        userId = userId,
        userKeyBytes = Pbkdf2.userKey(password),
        deviceAuthKey = Pbkdf2.deviceAuthKey(devicePassword),
        serialNumber = serialNumber,
    )

    var sessionId: Int = 0
        private set

    val isConnected: Boolean get() = client.isEstablished()

    /**
     * Performs the full handshake. [toGateway] is where the gateway listens; [gatewayPump]
     * runs the gateway's inbound processing and routes replies back onto the wire.
     */
    fun connect(toGateway: Endpoint) {
        net.sendUnicast(endpoint, toGateway, client.buildSessionRequest())
    }

    /** Processes a datagram addressed to this panel. Returns true if it completed a handshake. */
    fun onDatagram(frame: ByteArray, toGateway: Endpoint): Boolean {
        val header = runCatching { io.bms.knxsecure.wire.KnxIpHeader.decode(frame) }.getOrNull() ?: return false
        return when (header.serviceType) {
            io.bms.knxsecure.wire.ServiceType.SECURE_SESSION_RESPONSE -> {
                val auth = runCatching { client.onSessionResponse(frame) }.getOrNull() ?: return false
                net.sendUnicast(endpoint, toGateway, auth)
                false
            }
            io.bms.knxsecure.wire.ServiceType.SECURE_WRAPPER -> {
                val status = runCatching { client.onStatusFrame(frame) }.getOrNull()
                if (status == SessionStatus.AUTH_SUCCESS) {
                    sessionId = client.sessionId
                    true
                } else false
            }
            else -> false
        }
    }

    fun writeGroup(toGateway: Endpoint, groupAddress: Int, value: Byte, tunnelSeq: Int = 0) {
        val inner = TunnelPackets.tunnelingRequest(1, tunnelSeq, TunnelPackets.groupWriteCemi(groupAddress, value))
        net.sendUnicast(endpoint, toGateway, client.seal(inner))
    }

    fun sendRaw(toGateway: Endpoint, frame: ByteArray) = net.sendUnicast(endpoint, toGateway, frame)

    fun keepAlive(toGateway: Endpoint) {
        if (client.isEstablished()) net.sendUnicast(endpoint, toGateway, client.buildKeepAlive())
    }

    fun disconnect(toGateway: Endpoint) {
        if (client.isEstablished()) net.sendUnicast(endpoint, toGateway, client.buildClose())
        client.close()
    }

    fun client(): SecureTunnelClient = client
}

/**
 * A routing-mode backbone device. It publishes secure multicast frames using its own group
 * time. A compromised one can be told to announce an arbitrary time — with a *valid MAC*,
 * because it holds the group key.
 */
class SimRoutingDevice(
    val name: String,
    private val groupKey: AesKey,
    val serialNumber: Long,
    private val clock: VirtualClock,
    initialGroupTime: Long = 0,
) {
    var groupTime: Long = initialGroupTime

    fun advance(deltaMs: Long) {
        groupTime += deltaMs
    }

    fun publish(inner: ByteArray): ByteArray =
        SecureFrames.wrapMulticast(groupKey, groupTime, serialNumber, tag(), inner)

    fun announce(timestamp: Long = groupTime): ByteArray =
        SecureFrames.groupSync(groupKey, timestamp, serialNumber, tag())

    private var messageTag = (serialNumber and 0xffff).toInt()
    private fun tag(): Int {
        messageTag = (messageTag + 1) and 0xffff
        return messageTag
    }

    companion object {
        fun cemiGroupWrite(source: Int, groupAddress: Int, value: Byte): ByteArray = byteArrayOf(
            0x11, 0x00, (0x80 or 0x20).toByte(), 0x00,
            (source shr 8).toByte(), source.toByte(),
            (groupAddress shr 8).toByte(), groupAddress.toByte(),
            0x01, 0x00, value,
        )
    }
}
