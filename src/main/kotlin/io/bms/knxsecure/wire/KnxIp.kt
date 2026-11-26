package io.bms.knxsecure.wire

import io.bms.knxsecure.util.Bytes

/** KNXnet/IP service type identifiers used by the secure tunnel gateway. */
object ServiceType {
    const val SEARCH_REQUEST = 0x0201
    const val SEARCH_RESPONSE = 0x0202
    const val DESCRIPTION_REQUEST = 0x0203
    const val DESCRIPTION_RESPONSE = 0x0204
    const val CONNECT_REQUEST = 0x0205
    const val CONNECT_RESPONSE = 0x0206
    const val CONNECTIONSTATE_REQUEST = 0x0207
    const val CONNECTIONSTATE_RESPONSE = 0x0208
    const val DISCONNECT_REQUEST = 0x0209
    const val DISCONNECT_RESPONSE = 0x020A

    const val TUNNELLING_REQUEST = 0x0420
    const val TUNNELLING_ACK = 0x0421

    const val ROUTING_INDICATION = 0x0530
    const val ROUTING_LOST_MESSAGE = 0x0531
    const val ROUTING_BUSY = 0x0532
    const val ROUTING_SYSTEM_BROADCAST = 0x0533

    // KNX IP Secure
    const val SECURE_WRAPPER = 0x0950
    const val SECURE_SESSION_REQUEST = 0x0951
    const val SECURE_SESSION_RESPONSE = 0x0952
    const val SECURE_SESSION_AUTH = 0x0953
    const val SECURE_SESSION_STATUS = 0x0954
    const val SECURE_GROUP_SYNC = 0x0955

    const val PROTOCOL_VERSION_10 = 0x10

    fun name(type: Int): String = when (type) {
        SEARCH_REQUEST -> "search.req"
        SEARCH_RESPONSE -> "search.res"
        CONNECT_REQUEST -> "connect.req"
        CONNECT_RESPONSE -> "connect.res"
        CONNECTIONSTATE_REQUEST -> "connectionstate.req"
        CONNECTIONSTATE_RESPONSE -> "connectionstate.res"
        DISCONNECT_REQUEST -> "disconnect.req"
        DISCONNECT_RESPONSE -> "disconnect.res"
        TUNNELLING_REQUEST -> "tunnelling.req"
        TUNNELLING_ACK -> "tunnelling.ack"
        ROUTING_INDICATION -> "routing.ind"
        SECURE_WRAPPER -> "secure-wrapper"
        SECURE_SESSION_REQUEST -> "session.req"
        SECURE_SESSION_RESPONSE -> "session.res"
        SECURE_SESSION_AUTH -> "session-auth"
        SECURE_SESSION_STATUS -> "session-status"
        SECURE_GROUP_SYNC -> "group-sync"
        else -> "0x%04x".format(type)
    }

    /** True for 0x09xx service types that are wrapped/authenticated frames. */
    fun isSecureService(type: Int): Boolean = (type and 0xff00) == 0x0900
}

/**
 * A parsed KNXnet/IP header.
 *
 * Wire layout (6 bytes): structure length, protocol version, service type (16), total
 * length (16). The version is always 0x10 for the services used here.
 */
data class KnxIpHeader(
    val serviceType: Int,
    val totalLength: Int,
    val version: Int = ServiceType.PROTOCOL_VERSION_10,
) {
    init {
        require(serviceType in 0..0xffff) { "service type out of range" }
        require(totalLength >= HEADER_BYTES) { "total length must be >= $HEADER_BYTES" }
        require(totalLength <= 0xffff) { "total length exceeds 16 bits" }
        require(version in 0..0xff) { "version out of range" }
    }

    val bodyLength: Int get() = totalLength - HEADER_BYTES

    fun encode(): ByteArray = ByteArray(HEADER_BYTES).also { out ->
        out[0] = HEADER_BYTES.toByte()
        out[1] = version.toByte()
        Bytes.putU16(out, 2, serviceType)
        Bytes.putU16(out, 4, totalLength)
    }

    companion object {
        const val HEADER_BYTES = 6

        fun decode(data: ByteArray, offset: Int = 0): KnxIpHeader {
            if (data.size - offset < HEADER_BYTES) throw ProtocolFormatException("frame shorter than KNXnet/IP header")
            if (Bytes.u8(data, offset) != HEADER_BYTES) {
                throw ProtocolFormatException("unsupported KNXnet/IP header length ${Bytes.u8(data, offset)}")
            }
            val version = Bytes.u8(data, offset + 1)
            val service = Bytes.u16(data, offset + 2)
            val total = Bytes.u16(data, offset + 4)
            if (total < HEADER_BYTES) throw ProtocolFormatException("declared total length $total < header size")
            if (offset + total > data.size) {
                throw ProtocolFormatException("declared total length $total exceeds datagram size ${data.size - offset}")
            }
            return KnxIpHeader(service, total, version)
        }
    }
}

/**
 * Host Protocol Address Information (HPAI), 8 bytes:
 * length(1)=8, host protocol(1), IPv4 address(4), UDP/TCP port(2).
 */
data class Hpai(val hostProtocol: Int, val address: ByteArray, val port: Int) {

    init {
        require(address.size == 4) { "HPAI IPv4 address must be 4 bytes" }
        require(port in 0..0xffff) { "port out of range" }
        require(hostProtocol == IPV4_UDP || hostProtocol == IPV4_TCP) { "unsupported host protocol $hostProtocol" }
    }

    fun encode(): ByteArray = ByteArray(SIZE).also { out ->
        out[0] = SIZE.toByte()
        out[1] = hostProtocol.toByte()
        System.arraycopy(address, 0, out, 2, 4)
        Bytes.putU16(out, 6, port)
    }

    val isNat: Boolean get() = address.all { it == 0.toByte() } && port == 0

    fun ipString(): String = address.joinToString(".") { (it.toInt() and 0xff).toString() }

    override fun toString(): String =
        "${if (hostProtocol == IPV4_UDP) "udp" else "tcp"}://${if (isNat) "NAT" else ipString()}:$port"

    // data class with ByteArray: implement equals/hashCode on content
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Hpai) return false
        return hostProtocol == other.hostProtocol && address.contentEquals(other.address) && port == other.port
    }

    override fun hashCode(): Int = (hostProtocol * 31 + address.contentHashCode()) * 31 + port

    companion object {
        const val SIZE = 8
        const val IPV4_UDP = 0x01
        const val IPV4_TCP = 0x02

        val NAT = Hpai(IPV4_UDP, ByteArray(4), 0)

        fun decode(data: ByteArray, offset: Int): Hpai {
            if (data.size - offset < SIZE) throw ProtocolFormatException("HPAI truncated")
            if (Bytes.u8(data, offset) != SIZE) throw ProtocolFormatException("invalid HPAI length")
            val proto = Bytes.u8(data, offset + 1)
            val addr = data.copyOfRange(offset + 2, offset + 6)
            val port = Bytes.u16(data, offset + 6)
            return Hpai(proto, addr, port)
        }
    }
}

/** Thrown for structurally invalid frames (distinct from authentication failures). */
class ProtocolFormatException(message: String) : Exception(message)
