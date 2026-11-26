package io.bms.knxsecure.util

import java.security.MessageDigest

/**
 * Byte-level helpers shared by the wire codecs and crypto layer.
 *
 * KNX/IP is big-endian ("network order") for every multi-byte field, including the 48-bit
 * sequence number / multicast timestamp.
 */
object Bytes {

    fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
        for (b in bytes) {
            val v = b.toInt() and 0xff
            append(HEX[v ushr 4])
            append(HEX[v and 0x0f])
        }
    }

    fun hex(bytes: ByteArray, offset: Int, length: Int): String =
        hex(bytes.copyOfRange(offset, offset + length))

    fun unhex(s: String): ByteArray {
        val clean = s.filterNot { it == ' ' || it == '-' || it == ':' || it == '\n' || it == '\t' }
        require(clean.length % 2 == 0) { "hex string of odd length" }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "invalid hex character at index ${i * 2}" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun u8(b: ByteArray, off: Int): Int = b[off].toInt() and 0xff

    fun u16(b: ByteArray, off: Int): Int = (u8(b, off) shl 8) or u8(b, off + 1)

    fun u32(b: ByteArray, off: Int): Long =
        (u16(b, off).toLong() shl 16) or u16(b, off + 2).toLong()

    /** Reads a 48-bit big-endian unsigned value (sequence number / multicast timestamp). */
    fun u48(b: ByteArray, off: Int): Long =
        ((u16(b, off).toLong()) shl 32) or u32(b, off + 2)

    fun u64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }

    fun putU16(dst: ByteArray, off: Int, v: Int) {
        require(v in 0..0xffff) { "u16 out of range: $v" }
        dst[off] = (v ushr 8).toByte()
        dst[off + 1] = v.toByte()
    }

    fun putU32(dst: ByteArray, off: Int, v: Long) {
        require(v in 0..0xffff_ffffL) { "u32 out of range: $v" }
        dst[off] = (v ushr 24).toByte()
        dst[off + 1] = (v ushr 16).toByte()
        dst[off + 2] = (v ushr 8).toByte()
        dst[off + 3] = v.toByte()
    }

    fun putU48(dst: ByteArray, off: Int, v: Long) {
        require(v in 0..MAX_U48) { "u48 out of range: $v" }
        dst[off] = (v ushr 40).toByte()
        dst[off + 1] = (v ushr 32).toByte()
        dst[off + 2] = (v ushr 24).toByte()
        dst[off + 3] = (v ushr 16).toByte()
        dst[off + 4] = (v ushr 8).toByte()
        dst[off + 5] = v.toByte()
    }

    fun encodeU16(v: Int): ByteArray = ByteArray(2).also { putU16(it, 0, v) }

    fun encodeU32(v: Long): ByteArray = ByteArray(4).also { putU32(it, 0, v) }

    fun encodeU48(v: Long): ByteArray = ByteArray(6).also { putU48(it, 0, v) }

    fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var o = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, o, p.size)
            o += p.size
        }
        return out
    }

    /**
     * Constant-time comparison, used for every authentication tag / MAC check.
     * [MessageDigest.isEqual] is documented as time-constant for equal-length inputs.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        return MessageDigest.isEqual(a, b)
    }

    /** Best-effort wipe of sensitive material (keys, password buffers). */
    fun wipe(vararg arrays: ByteArray?) {
        for (a in arrays) a?.fill(0)
    }

    fun xor(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): ByteArray {
        require(aOff + len <= a.size && bOff + len <= b.size) { "xor range out of bounds" }
        val out = ByteArray(len)
        for (i in 0 until len) out[i] = (a[aOff + i].toInt() xor b[bOff + i].toInt()).toByte()
        return out
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** Reverse a byte array (little-endian <-> big-endian). */
    fun reversed(a: ByteArray): ByteArray {
        val out = ByteArray(a.size)
        for (i in a.indices) out[i] = a[a.size - 1 - i]
        return out
    }

    /** Left-pads a big-endian magnitude to [size] bytes. */
    fun padLeft(a: ByteArray, size: Int): ByteArray {
        if (a.size == size) return a.copyOf()
        require(a.size <= size) { "value does not fit into $size bytes" }
        val out = ByteArray(size)
        System.arraycopy(a, 0, out, size - a.size, a.size)
        return out
    }

    fun isAllZero(a: ByteArray): Boolean {
        var acc = 0
        for (b in a) acc = acc or b.toInt()
        return acc == 0
    }

    /** Unsigned 48-bit maximum. */
    const val MAX_U48: Long = 0xffff_ffff_ffffL

    /**
     * Highest sequence number at which a tunnel session must be closed and re-established,
     * leaving a safety margin before the 48-bit counter wraps (KNX IP Secure requirement).
     */
    const val SEQ_CLOSE_THRESHOLD: Long = 0xff00_0000_0000L

    private val HEX = "0123456789abcdef".toCharArray()
}
