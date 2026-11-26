package io.bms.knxsecure.multicast

import io.bms.knxsecure.crypto.AesKey
import io.bms.knxsecure.crypto.KnxSecureException
import io.bms.knxsecure.crypto.MacVerificationException
import io.bms.knxsecure.crypto.ProtocolException
import io.bms.knxsecure.util.MonotonicClock
import io.bms.knxsecure.wire.GroupSync
import io.bms.knxsecure.wire.KnxIpHeader
import io.bms.knxsecure.wire.SecureFrameVerifier
import io.bms.knxsecure.wire.SecureFrames
import io.bms.knxsecure.wire.SecureWrapper
import io.bms.knxsecure.wire.ServiceType

/**
 * Routing (multicast) side of the gateway.
 *
 * On the backbone, secure routing frames (`0x0950`, session id 0) and group-sync frames
 * (`0x0955`) are broadcast to the whole group. The gateway must:
 *
 *  1. **Never trust a group-sync as a clock.** It goes through [TimeSyncGuard], which bounds
 *     how far a single — or even a corroborated — announcement may move the estimate.
 *     The MAC on a group-sync proves possession of the shared backbone key, which is exactly
 *     the threat model: one compromised device holds it.
 *  2. **Authenticate every data frame before acting on it**, then apply the guard's verdict
 *     to its timestamp. Order matters: the timestamp is inside the MAC, so it cannot be
 *     changed by a network attacker at all; the guard defends against a *key-holding* peer.
 *  3. **Answer stale peers with a group-sync**, so a panel that rebooted with a near-zero
 *     timestamp converges in one round trip instead of being starved. Answers are rate
 *     limited so a reboot storm turns into a small number of syncs, not a broadcast storm.
 *
 * Like the session manager, this class is pure state and returns actions; the transport is
 * supplied by the caller.
 */
class SecureRoutingReceiver(
    private val groupKey: AesKey,
    private val clock: MonotonicClock,
    private val guard: TimeSyncGuard,
    val serialNumber: Long,
    private val config: Config = Config(),
) {
    private val verifier = SecureFrameVerifier()

    /** Counter used for the 16-bit routing message tag; wraps, as KNX specifies. */
    private var messageTag = (serialNumber and 0xffff).toInt()
    private var lastSyncSentMs = Long.MIN_VALUE
    private var syncsSent = 0L

    data class Config(
        /** Minimum spacing between our own group-sync responses to stale peers. */
        val minSyncResponseIntervalMs: Long = 200,
        /** Minimum spacing between our own periodic group-sync announcements. */
        val periodicSyncIntervalMs: Long = 10_000,
    )

    /** What the caller should do with a received multicast datagram. */
    data class Outcome(
        /** Verified inner KNXnet/IP packets to deliver to the bus. */
        val busPackets: List<ByteArray> = emptyList(),
        /** True if this datagram was a group-sync that updated the time estimate. */
        val wasGroupSync: Boolean = false,
        /** The guard's decision, when the datagram carried a timestamp. */
        val decision: TimeSyncGuard.Decision? = null,
        /** A group-sync frame to broadcast (rate limited). */
        val groupSyncToSend: ByteArray? = null,
        val droppedReason: String? = null,
    )

    /**
     * Processes one multicast datagram.
     *
     * @return the outcome; security alarms are delivered through [TimeSyncGuard.onAlarm].
     */
    fun onDatagram(frame: ByteArray): Outcome {
        val header = try {
            KnxIpHeader.decode(frame)
        } catch (e: ProtocolException) {
            return Outcome(droppedReason = "malformed: ${e.message}")
        }

        return try {
            when (header.serviceType) {
                ServiceType.SECURE_GROUP_SYNC -> onGroupSync(frame)
                ServiceType.SECURE_WRAPPER -> onRoutingData(frame)
                else -> Outcome(droppedReason = "not a secure routing service: ${ServiceType.name(header.serviceType)}")
            }
        } catch (e: MacVerificationException) {
            Outcome(droppedReason = "authentication failed")
        } catch (e: ProtocolException) {
            Outcome(droppedReason = "malformed: ${e.message}")
        } catch (e: KnxSecureException) {
            Outcome(droppedReason = "security failure: ${e.message}")
        }
    }

    private fun onGroupSync(frame: ByteArray): Outcome {
        val sync: GroupSync = verifier.openGroupSync(groupKey, frame)
        val decision = guard.observeTimerNotify(sync.timestamp, sync.serialNumber)
        return Outcome(
            wasGroupSync = true,
            decision = decision,
            // A group-sync from a stale peer (typically after a reboot) is answered so the
            // peer stops being starved, but only at a bounded rate.
            groupSyncToSend = maybeBuildSync(decision),
        )
    }

    private fun onRoutingData(frame: ByteArray): Outcome {
        val wrapper: SecureWrapper = verifier.openWrapper(groupKey, frame)
        if (!wrapper.isMulticast) {
            return Outcome(droppedReason = "unicast wrapper on the routing group")
        }
        val decision = guard.observeDataFrame(wrapper.sequence, wrapper.serialNumber)
        if (!decision.deliverable) {
            return Outcome(decision = decision, groupSyncToSend = maybeBuildSync(decision))
        }
        return Outcome(
            busPackets = listOf(wrapper.payload),
            decision = decision,
            groupSyncToSend = maybeBuildSync(decision),
        )
    }

    private fun maybeBuildSync(decision: TimeSyncGuard.Decision): ByteArray? {
        if (!decision.resyncSuggested) return null
        if (!guard.isAnchored()) return null
        // Never advertise a timestamp we believe is inflated, and never let one stale peer
        // trigger a sync storm.
        if (guard.isSuspectedInflated()) return null
        val now = clock.nowMs()
        if (lastSyncSentMs != Long.MIN_VALUE && now - lastSyncSentMs < config.minSyncResponseIntervalMs) return null
        lastSyncSentMs = now
        syncsSent++
        val tag = nextTag()
        return SecureFrames.groupSync(groupKey, guard.groupTimeNow(), serialNumber, tag)
    }

    /** Builds a periodic group-sync frame, or null if the guard says we must not be authoritative. */
    fun buildPeriodicSync(force: Boolean = false): ByteArray? {
        if (!guard.isAnchored() || guard.isSuspectedInflated() || guard.isDriftCeilingReached()) return null
        val now = clock.nowMs()
        if (!force && lastSyncSentMs != Long.MIN_VALUE && now - lastSyncSentMs < config.periodicSyncIntervalMs) {
            return null
        }
        lastSyncSentMs = now
        syncsSent++
        return SecureFrames.groupSync(groupKey, guard.groupTimeNow(), serialNumber, nextTag())
    }

    /** Wraps an outbound inner packet as a multicast secure routing frame. */
    fun sealRouting(inner: ByteArray): ByteArray {
        val ts = guard.groupTimeNow()
        return SecureFrames.wrap(groupKey, 0, ts, serialNumber, nextTag(), inner)
    }

    fun timeGuard(): TimeSyncGuard = guard
    fun syncsSentCount(): Long = syncsSent

    private fun nextTag(): Int {
        messageTag = (messageTag + 1) and 0xffff
        return messageTag
    }
}
