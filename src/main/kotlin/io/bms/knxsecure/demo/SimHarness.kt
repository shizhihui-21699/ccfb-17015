package io.bms.knxsecure.demo

import io.bms.knxsecure.SecureGateway
import io.bms.knxsecure.multicast.TimeSyncGuard
import io.bms.knxsecure.session.GatewayCredentials
import io.bms.knxsecure.session.GatewayEvent
import io.bms.knxsecure.session.GatewayPolicy
import io.bms.knxsecure.session.UserAccount
import io.bms.knxsecure.sim.SimNetwork
import io.bms.knxsecure.sim.SimPanel
import io.bms.knxsecure.sim.SimPasswords
import io.bms.knxsecure.sim.SimRoutingDevice
import io.bms.knxsecure.util.VirtualClock
import io.bms.knxsecure.wire.Endpoint

/**
 * Scenario harness shared by the demo and the integration tests.
 *
 * It holds a [SecureGateway] and a [SimNetwork] and knows how to pump traffic between them,
 * so scenarios read as plain prose instead of transport plumbing.
 */
class SimHarness(
    val policy: GatewayPolicy = GatewayPolicy(),
    timeSyncConfig: TimeSyncGuard.Config = TimeSyncGuard.Config(),
    routing: Boolean = true,
) {
    val clock = VirtualClock()
    val net = SimNetwork(clock)
    val gatewayEndpoint = Endpoint.of("10.0.0.1", 3671)

    val events = ArrayList<GatewayEvent>()
    val alarms = ArrayList<Pair<TimeSyncGuard.Alarm, String>>()

    val gateway = SecureGateway(
        credentials = GatewayCredentials(
            deviceAuthKey = io.bms.knxsecure.crypto.AesKey.of(SimPasswords.deviceKey),
            users = listOf(UserAccount(1, SimPasswords.userKey)),
        ),
        clock = clock,
        policy = policy,
        serialNumber = 0x010203040506L,
        groupKey = if (routing) SimPasswords.groupKey else null,
        timeSyncConfig = timeSyncConfig,
    ).also { gw ->
        gw.onEvent { events += it }
        gw.onTimeAlarm { a, d -> alarms += a to d }
    }

    /** Delivers everything queued for the gateway and routes its replies back to panels. */
    fun pump() {
        for (dg in net.drainUnicast(gatewayEndpoint)) {
            val handling = gateway.onUnicast(dg.from, dg.frame)
            for (p in handling.busPackets) net.publishToBus(p)
            for (r in handling.responses) net.sendUnicast(gatewayEndpoint, dg.from, r)
        }
        for (dg in net.drainMulticast()) {
            val outcome = gateway.onMulticast(dg.frame)
            for (p in outcome.busPackets) net.publishToBus(p)
            outcome.groupSyncToSend?.let { net.broadcastMulticast(it) }
        }
    }

    /** Drives all queued replies to panels. Returns number of handshakes that completed. */
    fun pumpPanels(panels: List<SimPanel>): Int {
        var completed = 0
        // Repeat until no more traffic moves: handshake responses can trigger auth frames.
        repeat(4) {
            for (p in panels) {
                for (dg in net.drainUnicast(p.endpoint)) {
                    if (p.onDatagram(dg.frame, gatewayEndpoint)) completed++
                }
            }
            pump()
        }
        return completed
    }

    fun panel(name: String, port: Int, serial: Long, addr: Int, password: String = SimPasswords.USER) =
        SimPanel(
            name = name,
            individualAddress = addr,
            endpoint = Endpoint.of("10.0.1.${(port % 200) + 10}", port),
            serialNumber = serial,
            net = net,
            clock = clock,
            password = password,
        )

    fun routingDevice(name: String, serial: Long) =
        SimRoutingDevice(name, SimPasswords.groupKey, serial, clock)
}
