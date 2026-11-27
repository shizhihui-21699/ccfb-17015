package knxsec

/** 可手动推进的时钟，测试与演示用它获得确定性时间。 */
class ManualClock(var t: Long = 1_000_000L) {
    fun now(): Long = t
    fun advance(ms: Long) {
        require(ms >= 0) { "时钟只能前进" }
        t += ms
    }
}

fun be16(v: Int): ByteArray = byteArrayOf((v ushr 8).toByte(), v.toByte())

fun be48(v: Long): ByteArray = ByteArray(6) { i -> (v ushr (8 * (5 - i))).toByte() }

fun be64(v: Long): ByteArray = ByteArray(8) { i -> (v ushr (8 * (7 - i))).toByte() }

fun ByteArray.rd16(off: Int): Int =
    ((this[off].toInt() and 0xFF) shl 8) or (this[off + 1].toInt() and 0xFF)

fun ByteArray.rd48(off: Int): Long {
    var v = 0L
    for (i in 0..5) v = (v shl 8) or (this[off + i].toLong() and 0xFF)
    return v
}

fun ByteArray.rd64(off: Int): Long {
    var v = 0L
    for (i in 0..7) v = (v shl 8) or (this[off + i].toLong() and 0xFF)
    return v
}
