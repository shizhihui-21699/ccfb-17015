package knxsec

/** 令牌桶限流器。 */
class TokenBucket(
    val capacity: Double,
    val refillPerSec: Double,
    private val now: () -> Long,
) {
    private var tokens = capacity
    private var last = now()

    @Synchronized
    fun tryConsume(n: Double = 1.0): Boolean {
        val t = now()
        tokens = minOf(capacity, tokens + (t - last) / 1000.0 * refillPerSec)
        last = t
        if (tokens >= n) {
            tokens -= n
            return true
        }
        return false
    }
}

/**
 * 按来源 IP 的限流器。表项有上限并 LRU 驱逐，
 * 防止攻击者用大量伪造源 IP 撑爆内存（这本身也是一种耗尽攻击）。
 */
class PerKeyRateLimiter(
    private val capacity: Double,
    private val refillPerSec: Double,
    private val now: () -> Long,
    private val maxKeys: Int = 4096,
) {
    private val buckets = object : LinkedHashMap<String, TokenBucket>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, TokenBucket>?) = size > maxKeys
    }

    @Synchronized
    fun tryConsume(key: String): Boolean =
        buckets.getOrPut(key) { TokenBucket(capacity, refillPerSec, now) }.tryConsume()
}
