# KNX IP Secure tunnel gateway (Kotlin/JVM)

A security **session layer** for a KNX IP Secure tunnel gateway in a high-end office
building, plus a simulated device lab that exercises it. The building automation system runs
KNX IP Secure over a multicast backbone; this code implements the gateway's secure endpoints:

* **Session request phase** — X25519 ephemeral key exchange (`0x0951`/`0x0952`)
* **Session authentication phase** — user password derived with PBKDF2-HMAC-SHA256 (`0x0953`)
* **Secure encapsulation** — 48-bit sequence numbers and 128-bit CCM authentication tags
  (`0x0950`)
* **Multicast routing time base** — hardened handling of `0x0955` timer notifications
* **Anti-exhaustion** — bounded handshake state and admission control

## Why this is non-trivial

Two things in the brief are genuinely hard, and they are where the design effort went.

### 1. The multicast time base is an attack surface

On a secure backbone every routing frame carries a 48-bit **group timestamp**, not a
per-session counter. A receiver delivers a frame only if its timestamp is within a *latency
tolerance* (1–8000 ms) of its own estimate of group time. That estimate is synchronised by
`0x0955` group-sync frames, which are authenticated **only with the shared backbone group
key** — which every secure device on the segment holds.

So the MAC proves *"some device with the group key said this"*, not *"this is true"*. A
compromised panel, a leaked key, or a mis-configured node can announce a time an hour in the
future; a naive receiver applies the whole difference to its offset, every legitimate frame
then looks expired, and **the entire segment goes silent**.

The insight the guard is built on is an asymmetry:

> A frame **ahead** of the estimate is fresh and must be delivered. A frame **behind** it is
> what the tolerance check drops. Therefore the only way to silence the segment is to push the
> estimate too far **ahead** — and being behind is always harmless, because the frames still
> arrive ahead of us.

So `TimeSyncGuard` never moves the clock *backwards* and treats *backward* claims as
irrelevant, while every rule constrains **forward** motion:

| Rule | Effect |
|---|---|
| **R1** ahead is deliverable | A frame that is early is never rejected for being early |
| **R2** bounded single step | One observation moves the clock by at most the tolerance |
| **R3** corroboration | A bigger jump needs 3 distinct senders within a window |
| **R4** slew + ceiling | Token bucket refills at 10 ms/s; cumulative drift is capped **at one tolerance** and relaxes only at a realistic crystal-skew rate (100 ppm), so a genuinely fast group is followed forever but a jump is not |
| **R5** monotonic output | Network input never moves the estimate backwards |
| **R6** freeze when suspect | If senders coherently disagree *after real forward drift was applied*, alarm + freeze |

The R4 cap is the load-bearing one. Because forward drift only ever helps an attacker
(a legitimately *faster* group needs no correction at all — its frames are early), the cap is
required to be **no larger than the latency tolerance**. That guarantees a genuine frame at
true group time can never be pushed out of the acceptance window, so a successful attack
degrades the segment by at most a couple of seconds and then latches
`FORWARD_DRIFT_CEILING_REACHED` until an operator resyncs.

This also dissolves the long-heartbeat problem for free: group time is
`anchor + elapsed local monotonic time`, **not** "the last timestamp seen". A six-hour
night-mode gap does not make legitimate frames look ancient.

### 2. Session exhaustion vs. the mass power-on

A flood of session requests could fill the gateway's tunnel table. But a whole floor of
panels energising together is a *normal, legitimate* version of the same traffic pattern, so
the defence cannot be a blunt per-second cap on session creation.

The design separates **identity from load**:

* Half-open handshakes live in a **pending** table, never in the tunnel table. They expire
  after 10 s, are capped globally and per source, and on overflow the **oldest pending entry is
  evicted** — an unauthenticated request has no claim on the resource.
* A tunnel slot is consumed **only after** the user-key MAC verifies. A spoofing attacker
  that cannot authenticate can therefore occupy **zero** slots.
* Expensive work (PBKDF2 65 536 rounds + X25519) is gated by a concurrency limit, so a flood
  cannot pin every core.
* When the established table is full, a new authenticated client evicts the **least-recently
  used idle** session (idle ≥ 30 s), so a power-on burst is not starved behind stale entries.

The tests prove both halves: 3 000 spoofed half-open requests occupy **0** tunnel slots and a
real client still connects; 200 panels power on within one second and **all 200** establish.

## Wire-format interoperability

Interoperability is the reason this format exists, so the codec is validated byte-for-byte
against the reference KNX IP Secure implementation (`calimero-core 3.0-M1`) and against the
standards:

* X25519 — **RFC 7748 §6.1** known-answer vectors
* PBKDF2 — verified against reference-derived KNX user/device keys
* Secure wrapper, multicast wrapper, group-sync — **byte-identical** to reference frames
* CBC-MAC / CCM construction — verified at each intermediate value

`WireInteropTest` pins the exact hex; `gradle demo` prints our frame next to the reference
frame so the match is visible.

## Layout

```
src/main/kotlin/io/bms/knxsecure/
├── crypto/      X25519, PBKDF2, KNX AES-CCM profile, exceptions
├── wire/        KNXnet/IP header, HPAI, secure frame codec + verifier
├── session/     handshake, sequence tracker, tunnel session, session manager, policy
├── multicast/   TimeSyncGuard (the clock defence), SecureRoutingReceiver
├── client/      faithful client-side tunnel (used by the simulator and tests)
├── sim/         simulated panels, routing devices, in-process wire
├── demo/        `gradle demo` scenario runner
└── SecureGateway.kt   facade tying unicast + multicast together
```

The gateway is **pure state**: it takes datagrams in and returns datagrams out, with no
sockets, threads, or I/O. All time flows through `MonotonicClock`, so every scenario is
deterministic under `VirtualClock`.

## Build and run

Requires a JDK (17+) and Gradle. Everything builds offline once dependencies are cached.

```bash
gradle build          # compile + run all 100 tests
gradle test           # tests only
gradle demo           # nine narrated scenarios (see below)
```

### Demo scenarios

1. Session handshake and encrypted tunnel traffic
2. Wire-format interoperability with reference frames
3. Replay, cross-session injection and tampering
4. Session-exhaustion attack and its containment
5. Legitimate mass power-on (200 panels in ~1 s)
6. Night mode (long heartbeat gaps, both tunnel and routing)
7. **Attack:** forged future timer notification
8. **Attack:** sustained corroborated forward push
9. **Legitimate:** mass reboot with stale timestamps

## Using the gateway

```kotlin
val gateway = SecureGateway(
    credentials = GatewayCredentials(
        deviceAuthKey = AesKey.of(Pbkdf2.deviceAuthKey("device-code")),
        users = listOf(UserAccount(1, Pbkdf2.userKey("installer-password"))),
    ),
    clock = SystemMonotonicClock,
    policy = GatewayPolicy(maxSessions = 256),
    groupKey = AesKey.of(backboneKey16Bytes),   // enables routing mode
)

// Unicast datagram arrived:
val handling = gateway.onUnicast(sourceEndpoint, datagram)
handling.busPackets.forEach { bus.write(it) }      // verified inner KNXnet/IP packets
handling.responses.forEach { socket.send(it) }     // to the source

// Multicast datagram arrived:
val outcome = gateway.onMulticast(datagram)
outcome.busPackets.forEach { bus.write(it) }
outcome.groupSyncToSend?.let { multicastSocket.send(it) }  // already rate limited

// Monitoring:
gateway.onEvent { event -> log.info(event) }
gateway.onTimeAlarm { alarm, detail -> alert(alarm, detail) }  // forward-drift, suspected inflation
```

Operational notes:

* `hardResync` is the only way to re-anchor after `FORWARD_DRIFT_CEILING_REACHED` or
  `CLOCK_SUSPECTED_INFLATED`. It trusts its input completely, so expose it **only** through an
  authenticated management path (ETS download / device-management session), never on a
  network listener.
* The long-term secrets are the **passwords**, since KNX PBKDF2 uses fixed salts. Choose them
  with real entropy and rely on the built-in authentication back-off.

## Testing approach

100 tests across seven suites, all deterministic on a virtual clock:

| Suite | Covers |
|---|---|
| `CryptoVectorsTest` | RFC vectors, PBKDF2, CCM intermediates |
| `WireInteropTest` | Byte-exact reference frames, tampering, truncation |
| `SessionHandshakeTest` | MAC binding, MITM detection, user/key mismatch |
| `GatewaySessionTest` | Handshake, replay, injection, exhaustion, power-on, night mode |
| `TimeSyncGuardTest` | Each rule individually, plus attack and legitimate-blip scenarios |
| `SecureRoutingTest` | End-to-end multicast attacks with real MACs |
| `EndToEndScenarioTest` | The demo scenarios as assertions |

The attack tests all use **valid MACs** produced with the group key, because a network
attacker without the key cannot get past authentication at all — the interesting threat is a
key-holding one.

## Known limitations

* No real UDP socket binding is included; `SecureGateway` is transport-agnostic by design and
  the simulator stands in for the network. Wiring it to a `DatagramChannel` is a small adapter.
* KNX IP Secure device management (`0x0950` over device-management services) is not exposed.
* Tunnel *building* (connect.req/tunnelling.ack channel semantics) is simplified to the
  secure wrapper; the inner packets are passed through opaquely, which is correct for a
  routing gateway but not a full tunneling server.
* Best-effort key wiping: the JCE may copy key material internally, so `AesKey.close()` cannot
  guarantee erasure.
