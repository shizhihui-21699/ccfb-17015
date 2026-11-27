package knxsec

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * 密码学原语：
 * - X25519 ECDH（JDK 内建），对应 KNX IP Secure 会话请求阶段的密钥交换
 * - PBKDF2-HMAC-SHA256 口令派生（KNX 规范盐值，默认 65536 轮）
 * - AES-128-CCM（BouncyCastle 轻量 API），16 字节认证标签
 */
object Crypto {
    const val X25519_KEY_LEN = 32
    const val SESSION_KEY_LEN = 16
    const val TAG_LEN = 16
    const val NONCE_LEN = 13

    /** 测试可调小以加速；生产必须保持 65536。 */
    @Volatile
    var pbkdf2Iterations: Int = 65_536

    private val PASSWORD_SALT = "password-hash.1.secure.ip.knx.org".toByteArray(Charsets.US_ASCII)

    fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("X25519").generateKeyPair()

    /** X.509 编码的末 32 字节即 u 坐标。 */
    fun publicKeyBytes(pub: PublicKey): ByteArray =
        pub.encoded.copyOfRange(pub.encoded.size - X25519_KEY_LEN, pub.encoded.size)

    /** PKCS#8 编码的末 32 字节即标量。 */
    fun privateKeyBytes(priv: PrivateKey): ByteArray =
        priv.encoded.copyOfRange(priv.encoded.size - X25519_KEY_LEN, priv.encoded.size)

    fun publicKeyFromBytes(u: ByteArray): PublicKey {
        require(u.size == X25519_KEY_LEN) { "X25519 公钥必须为 32 字节" }
        // u 坐标在线为小端，XECPublicKeySpec 的 BigInteger 为大端
        val spec = XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger(1, u.reversedArray()))
        return KeyFactory.getInstance("X25519").generatePublic(spec)
    }

    fun privateKeyFromBytes(scalar: ByteArray): PrivateKey {
        require(scalar.size == X25519_KEY_LEN) { "X25519 私钥必须为 32 字节" }
        return KeyFactory.getInstance("X25519")
            .generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, scalar))
    }

    fun ecdh(priv: PrivateKey, pub: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    /** 用户口令 -> 16 字节认证密钥（KNX IP Secure 口令散列）。 */
    fun passwordKey(password: String): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), PASSWORD_SALT, pbkdf2Iterations, SESSION_KEY_LEN * 8)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    /** AES-CCM 加密，输出 = 密文 || 16 字节标签。 */
    fun ccmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        require(nonce.size == NONCE_LEN)
        val ccm = CCMBlockCipher(AESEngine())
        ccm.init(true, AEADParameters(KeyParameter(key), TAG_LEN * 8, nonce, aad))
        val out = ByteArray(ccm.getOutputSize(plain.size))
        var len = ccm.processBytes(plain, 0, plain.size, out, 0)
        len += ccm.doFinal(out, len)
        return out.copyOf(len)
    }

    /** AES-CCM 解密；标签校验失败返回 null（绝不返回部分明文）。 */
    fun ccmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertextAndTag: ByteArray): ByteArray? {
        require(nonce.size == NONCE_LEN)
        val ccm = CCMBlockCipher(AESEngine())
        ccm.init(false, AEADParameters(KeyParameter(key), TAG_LEN * 8, nonce, aad))
        return try {
            val out = ByteArray(ccm.getOutputSize(ciphertextAndTag.size))
            var len = ccm.processBytes(ciphertextAndTag, 0, ciphertextAndTag.size, out, 0)
            len += ccm.doFinal(out, len)
            out.copyOf(len)
        } catch (e: InvalidCipherTextException) {
            null
        }
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var r = 0
        for (i in a.indices) r = r or (a[i].toInt() xor b[i].toInt())
        return r == 0
    }
}
