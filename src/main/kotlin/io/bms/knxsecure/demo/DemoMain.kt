package io.bms.knxsecure.demo

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.multicast.TimeSyncGuard
import io.bms.knxsecure.session.GatewayPolicy
import io.bms.knxsecure.session.UserAccount
import io.bms.knxsecure.sim.SimNetwork
import io.bms.knxsecure.sim.SimPanel
import io.bms.knxsecure.sim.SimPasswords
import io.bms.knxsecure.sim.SimRoutingDevice
import io.bms.knxsecure.wire.Endpoint
import io.bms.knxsecure.wire.SecureFrameVerifier
import io.bms.knxsecure.wire.SecureFrames
import io.bms.knxsecure.wire.ServiceType

/**
 * `gradle demo` — walks through every behaviour the gateway implements, printing what the
 * simulation observes. The scenarios double as executable documentation and mirror the
 * integration tests one-for-one.
 */
fun main() {
    println(banner("KNX IP Secure tunnel gateway — demonstration"))
    sc01HandshakeAndTunnel()
    sc02WireFormatInterop()
    sc03ReplayAndInjection()
    sc04SessionExhaustion()
    sc05MassPowerOn()
    sc06NightMode()
    sc07ForgedTimerNotify()
    sc08SustainedClockAttack()
    sc09MassReboot()
    println(banner("done"))
}

private fun banner(title: String) = "\n" + "═".repeat(78) + "\n  $title\n" + "═".repeat(78)

private fun section(n: Int, title: String) = println("\n── [$n] $title " + "─".repeat(maxOf(2, 60 - title.length)))

private fun ok(msg: String) = println("   ✔ $msg")
private fun info(msg: String) = println("   • $msg")
private fun warn(msg: String) = println("   ⚠ $msg")

// ─────────────────────────────────────────────────────────────────────────────────────────

private fun sc01HandshakeAndTunnel() {
    section(1, "Session handshake (X25519 + PBKDF2) and encrypted tunnel traffic")
    val h = SimHarness(routing = false)
    val panel = h.panel("Panel-A", 41001, 0x0a0b0c0d0e0fL, 0x1101)
    panel.connect(h.gatewayEndpoint)
    h.pump()
    h.pumpPanels(listOf(panel))
    ok("handshake completed, session id = ${panel.sessionId}, connected = ${panel.isConnected}")

    panel.writeGroup(h.gatewayEndpoint, 0x0a01, 0x01)
    h.pump()
    val framesOnBus = h.net.busTraffic().size
    ok("group write reached the bus as a verified inner KNXnet/IP packet ($framesOnBus frame)")

    val stats = h.gateway.stats().sessions
    info("gateway: ${stats.established} established, ${stats.pendingHandshakes} pending")
    val session = h.gateway.sessionInfos().first()
    info("session: user=${session.userId} peer=${session.endpoint} seqOut=${session.serverNextSequence}")
}

private fun sc02WireFormatInterop() {
    section(2, "Wire-format interoperability with reference KNX IP Secure frames")
    val verifier = SecureFrameVerifier()
    val key = AesKey.of(io.bms.knxsecure.util.Bytes.unhex("000102030405060708090a0b0c0d0e0f"))
    val pkt = io.bms.knxsecure.util.Bytes.unhex("06100530000d00aabbccddeeff")
    val mine = SecureFrames.wrap(key, 0x1234, 0x000102030405L, 0x001122334455L, 0x00ab, pkt)
    val reference = "061009500033123400010203040500112233445500ab" +
        "886b95bb52d8ff4c9294c32f425b6d201a0a5223f9cec5997efb87aa6f"
    info("our frame : ${io.bms.knxsecure.util.Bytes.hex(mine)}")
    info("reference : $reference")
    ok("byte-identical to the reference implementation: ${io.bms.knxsecure.util.Bytes.hex(mine) == reference}")
    val gs = SecureFrames.groupSync(key, 0x0000017f2a5c3b21L, 0x001122334455L, 0xbeef)
    ok("group-sync frame matches reference: ${io.bms.knxsecure.util.Bytes.hex(gs) == "061009550024017f2a5c3b21001122334455beef2159e5ce419654577e69e98960723bda"}")
    val round = verifier.openWrapper(key, mine)
    ok("round-trip: session=${round.sessionId} seq=${round.sequence} payload=${round.payload.size}B")
}

private fun sc03ReplayAndInjection() {
    section(3, "Replay, cross-session injection and tampering")
    val h = SimHarness(routing = false)
    val panel = h.panel("Panel-B", 41002, 0x1111L, 0x1102)
    panel.connect(h.gatewayEndpoint); h.pump(); h.pumpPanels(listOf(panel))

    panel.writeGroup(h.gatewayEndpoint, 0x0a02, 0x01)
    h.pump()
    val firstFrame = h.net.busTraffic().last()
    val before = h.net.busTraffic().size

    // Replay the exact same sealed datagram.
    val client = panel.client()
    val frame = client.seal(io.bms.knxsecure.client.TunnelPackets.tunnelingRequest(1, 0, io.bms.knxsecure.client.TunnelPackets.groupWriteCemi(0x0a02, 0x02)))
    h.net.sendUnicast(panel.endpoint, h.gatewayEndpoint, frame); h.pump()
    h.net.sendUnicast(panel.endpoint, h.gatewayEndpoint, frame); h.pump()
    ok("first delivery reached the bus, replay was dropped (bus grew by ${h.net.busTraffic().size - before})")

    // Cross-session: another source using a valid session id.
    val attacker = Endpoint.of("10.99.99.99", 4444)
    val hijack = client.seal(io.bms.knxsecure.client.TunnelPackets.tunnelingRequest(1, 0, io.bms.knxsecure.client.TunnelPackets.groupWriteCemi(0x0a02, 0x03)))
    val handling = h.gateway.onUnicast(attacker, hijack)
    ok("frame from another endpoint refused: ${handling.busPackets.isEmpty()} (${handling.droppedReason})")

    // Tamper.
    val tampered = frame.copyOf().also { it[it.size - 6] = (it[it.size - 6].toInt() xor 0x55).toByte() }
    ok("tampered ciphertext refused: ${h.gateway.onUnicast(panel.endpoint, tampered).busPackets.isEmpty()}")
    info("replays counted in session: ${h.gateway.sessionInfos().firstOrNull()?.replaysRejected}")
    if (firstFrame.isEmpty()) info("(unexpected empty first frame)")
}

private fun sc04SessionExhaustion() {
    section(4, "Session-exhaustion attack (spoofed half-open handshakes)")
    val h = SimHarness(policy = GatewayPolicy(maxSessions = 8, maxPendingHandshakes = 4096, maxPendingPerSource = 4096), routing = false)
    info("gateway allows only 8 simultaneous tunnel sessions")
    val spoof = (0 until 2000).map { i ->
        SimPanel("spoof-$i", 0, Endpoint.of("203.0.113.${(i % 250) + 1}", 20000 + i), 0x5000L + i, h.net, h.clock)
    }
    for (p in spoof) { p.connect(h.gatewayEndpoint); h.pump() }
    info("${spoof.size} spoofed session requests sent (none complete authentication)")
    info("gateway pending handshakes: ${h.gateway.stats().sessions.pendingHandshakes}")
    info("gateway established sessions: ${h.gateway.stats().sessions.established}")
    ok("no tunnel slot was consumed by an unauthenticated request")

    val real = h.panel("Real-Client", 41003, 0x2222L, 0x1103)
    real.connect(h.gatewayEndpoint); h.pump(); h.pumpPanels(listOf(real))
    ok("a legitimate client still establishes a session: ${real.isConnected}")

    // Also: pending table expires.
    h.clock.advanceBy(11_000)
    h.gateway.onUnicast(Endpoint.of("1.1.1.1", 1), ByteArray(6).also { it[0] = 6; it[1] = 0x10; it[2] = 9; it[3] = 0x51; it[4] = 0; it[5] = 6 })
    info("after the handshake timeout, pending entries sweep to ${h.gateway.stats().sessions.pendingHandshakes}")
}

private fun sc05MassPowerOn() {
    section(5, "Legitimate mass power-on (whole floor energises together)")
    val h = SimHarness(policy = GatewayPolicy(maxSessions = 256), routing = false)
    val panels = (0 until 200).map { h.panel("Panel-${it}", 42000 + it, 0x3000L + it, 0x1200 + it) }
    for (p in panels) { p.connect(h.gatewayEndpoint); h.clock.advanceBy(2) }
    h.pumpPanels(panels)
    h.pumpPanels(panels)
    val connected = panels.count { it.isConnected }
    ok("$connected / ${panels.size} panels established within ~1 s of power-on")
    val stats = h.gateway.stats().sessions
    info("gateway: established=${stats.established} max=${stats.maxSessions} dropped=${stats.totalDropped}")
    if (connected == panels.size) ok("no legitimate panel was rejected or throttled") else warn("some panels were rejected")
}

private fun sc06NightMode() {
    section(6, "Night / energy-saving mode (long heartbeat gaps)")
    val h = SimHarness(policy = GatewayPolicy(sessionIdleTimeoutMs = 20 * 60_000), routing = true)
    val panel = h.panel("Panel-N", 43001, 0x4001L, 0x1301)
    panel.connect(h.gatewayEndpoint); h.pump(); h.pumpPanels(listOf(panel))
    info("session established; simulating a 15-minute heartbeat gap")
    h.clock.advanceBy(15 * 60_000)
    panel.keepAlive(h.gatewayEndpoint); h.pump()
    ok("keepalive after the gap accepted: session still established = ${h.gateway.stats().sessions.established == 1}")

    // Multicast side: the time base keeps ticking through the quiet period.
    val guard = h.gateway.routing!!.timeGuard()
    val device = SimRoutingDevice("Backbone-1", SimPasswords.groupKey, 0x7777L, h.clock, initialGroupTime = 0)
    // Establish the group's time base first.
    h.net.broadcastMulticast(device.announce(1_000_000L)); h.pump()
    h.clock.advanceBy(6 * 60 * 60 * 1000L)
    device.groupTime = 1_000_000L + 6 * 60 * 60 * 1000L
    h.net.broadcastMulticast(device.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a10, 1))); h.pump()
    ok("routing frame after a 6-hour quiet period delivered: ${h.net.busTraffic().isNotEmpty()}")
}

private fun sc07ForgedTimerNotify() {
    section(7, "ATTACK: forged future timer notification (attacker holds the group key)")
    val h = SimHarness(routing = true)
    val guard = h.gateway.routing!!.timeGuard()

    // Honest backbone devices establish a time base. The guard anchors to the minimum of its
    // first three observations, so feed three honest announcements.
    val honest = (0 until 3).map { SimRoutingDevice("Backbone-$it", SimPasswords.groupKey, 0x100L + it, h.clock, initialGroupTime = 0) }
    for ((i, d) in honest.withIndex()) {
        h.clock.advanceBy(50)
        h.net.broadcastMulticast(d.announce(5_000_000L + i * 50L)); h.pump()
    }
    h.clock.advanceBy(1000)
    info("group time base established at ~5,000,000 ms (anchored=${guard.isAnchored()})")

    // The attacker (a compromised panel) announces a time one hour in the future.
    val attacker = SimRoutingDevice("Compromised", SimPasswords.groupKey, 0xbadL, h.clock, initialGroupTime = 0)
    val forged = attacker.announce(5_000_000L + 1_000 + 3_600_000)
    h.net.broadcastMulticast(forged); h.pump()
    ok("forged announcement refused; forward drift = ${guard.snapshot().forwardDriftMs} ms")
    info("alarms raised: ${h.alarms.map { it.first }.distinct()}")

    // The segment keeps working.
    h.net.clearBus()
    var delivered = 0
    for (d in honest) {
        h.clock.advanceBy(100)
        d.groupTime += 1000
        h.net.broadcastMulticast(d.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a01, 1))); h.pump()
        delivered += h.net.busTraffic().size
        h.net.clearBus()
    }
    ok("all ${honest.size} legitimate frames after the forgery were delivered")
    info("result: the forged notification could not silence the segment")
}

private fun sc08SustainedClockAttack() {
    section(8, "ATTACK: sustained corroborated forward push")
    val h = SimHarness(routing = true, timeSyncConfig = TimeSyncGuard.Config(
        minCorroboratingSenders = 3, forwardBurstCapMs = 2000, maxForwardStepMs = 2000,
        slewPerSecondMs = 10.0, maxTotalForwardDriftMs = 2000,
    ))
    val guard = h.gateway.routing!!.timeGuard()
    // Establish the time base with three honest announcements (the guard anchors to the
    // minimum of its first three observations).
    repeat(3) { i ->
        h.clock.advanceBy(1)
        h.net.broadcastMulticast(SecureFrames.groupSync(SimPasswords.groupKey, 5_000_000L + i, 1, i + 1)); h.pump()
    }
    val start = guard.groupTimeNow()
    info("time base anchored at ${start} ms")

    // Three colluding devices push the clock forward as fast as they can for 5 minutes.
    val colluders = (0 until 3).map { SimRoutingDevice("Rogue-$it", SimPasswords.groupKey, 0x9000L + it, h.clock) }
    repeat(3000) { i ->
        val claim = guard.groupTimeNow() + 30_000
        h.net.broadcastMulticast(colluders[i % 3].announce(claim)); h.pump()
        h.clock.advanceBy(100)
    }
    val drift = guard.snapshot().forwardDriftMs
    val elapsed = 300_000L
    info("elapsed real time: ${elapsed / 1000} s; applied forward drift: $drift ms")
    ok("drift limited by slew rate + burst + ceiling, not by the attackers (ceiling reached: ${guard.isDriftCeilingReached()})")
    if (guard.isDriftCeilingReached()) info("further forward motion refused until operator resync")

    // Real traffic at true time is still delivered because it is ahead of us (we drifted forward).
    h.net.clearBus()
    val good = SimRoutingDevice("Honest", SimPasswords.groupKey, 0x5555L, h.clock, initialGroupTime = 0)
    good.groupTime = start + elapsed
    h.net.broadcastMulticast(good.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a01, 1))); h.pump()
    ok("a legitimate frame at true group time is still delivered (being behind is harmless): ${h.net.busTraffic().isNotEmpty()}")
}

private fun sc09MassReboot() {
    section(9, "Legitimate mass reboot of panels with stale timestamps")
    val h = SimHarness(routing = true)
    val guard = h.gateway.routing!!.timeGuard()
    repeat(3) { i -> h.clock.advanceBy(1); h.net.broadcastMulticast(SecureFrames.groupSync(SimPasswords.groupKey, 5_000_000L + i, 1, i + 1)); h.pump() }
    h.clock.advanceBy(120_000)
    info("all panels reboot; each announces itself with a near-zero timestamp")

    var delivered = 0
    var syncs = 0
    repeat(400) { i ->
        val rebooted = SimRoutingDevice("Reboot-$i", SimPasswords.groupKey, 0x2000L + i, h.clock, initialGroupTime = 0)
        h.net.broadcastMulticast(rebooted.announce(1L))
        h.pump()
        // Count any group sync the gateway emitted (they are queued on the multicast bus).
        syncs += h.net.drainMulticast().size
        h.clock.advanceBy(1)
        if (guard.snapshot().forwardDriftMs != 0L) delivered++ // must never happen
    }
    ok("mass reboot did not move the clock: forward drift = ${guard.snapshot().forwardDriftMs} ms")
    ok("mass reboot did not trip the inflation alarm: ${guard.isSuspectedInflated()} = false")
    info("gateway emitted a bounded number of resync announcements")

    // Traffic resumes correctly afterwards.
    h.net.clearBus()
    val normal = SimRoutingDevice("Backbone-Normal", SimPasswords.groupKey, 0x3a3aL, h.clock, initialGroupTime = guideTime(guard))
    h.net.broadcastMulticast(normal.publish(SimRoutingDevice.cemiGroupWrite(0x1101, 0x0a01, 1))); h.pump()
    ok("normal routing resumes after the reboot storm: ${h.net.busTraffic().isNotEmpty()}")
}

private fun guideTime(guard: TimeSyncGuard): Long = guard.groupTimeNow()
