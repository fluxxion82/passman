import java.lang.String
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.ByteArray
import kotlin.CharArray
import kotlin.Exception
import kotlin.Int
import kotlin.text.StringBuilder
import kotlin.text.isEmpty
import kotlin.text.toCharArray
import kotlin.text.toInt


/**
 * Calculate SHA-256 hash, with 1000 iterations by default (RSA PKCS5).
 *
 * @param text password text
 * @return hash of the password
 * @throws Exception if error occurred
 */
fun getPKCS5Sha256Hash(text: CharArray?): ByteArray {
    return getSha256Hash(text!!, 1000)
}

/**
 * Calculate SHA-256 hash.
 *
 * @param text password text
 * @return hash of the password
 * @throws Exception if error occurred
 */
fun getSha256Hash(text: CharArray): ByteArray {
    return getSha256Hash(text, 0)
}

/**
 * Calculate SHA-256 hash.
 *
 *
 *
 * To slow down the computation it is recommended to iterate the hash operation `n` times.
 * While hashing the password `n` times does slow down hashing for both attackers and
 * typical users, typical users don't really notice it being that hashing is such a small
 * percentage of their total time interacting with the system. On the other hand, an attacker
 * trying to crack passwords spends nearly 100% of their time hashing so hashing `n` times
 * gives the appearance of slowing the attacker down by a factor of `n` while not
 * noticeably affecting the typical user. A minimum of 1000 operations is recommended in RSA
 * PKCS5 standard.
 *
 * @param text password text
 * @param iteration number of iterations
 * @return hash of the password
 * @throws Exception if error occurred
 */
private fun getSha256Hash(text: CharArray, iteration: Int): ByteArray {
    val md: MessageDigest = MessageDigest.getInstance("SHA-256")
    md.reset()
    // md.update(salt);
    val bytes = String(text).bytes
    var digest = md.digest(bytes)
    for (i in 0 until iteration) {
        md.reset()
        digest = md.digest(digest)
    }
    return digest
}

fun generatePassword() {
    val random = SecureRandom()
    val characterSet = UPPER + LOWER + NUM + SYMBOLS
    characterSet.toCharArray().shuffle()
    characterSet.toCharArray().shuffle()

    if (characterSet.isEmpty()) {
        return
    }

    val generated = StringBuilder()
    val passwordLength: Int = String.valueOf(14).toInt()
    for (i in 0 until passwordLength) {
        generated.append(characterSet[random.nextInt(characterSet.length)])
    }
}

private const val SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~"
private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
private const val NUM = "0123456789"
