package ai.passman.platform.recovery

import ai.passman.platform.crypto.SecureRandomService
import org.web3j.crypto.MnemonicUtils

/** A standard English BIP39 phrase used directly as a portable-recovery P12 password. */
internal object Bip39RecoveryPhrase {
    const val WORD_COUNT = 24
    private const val ENTROPY_BYTES = 32

    fun generate(random: SecureRandomService): String {
        val entropy = random.nextBytes(ENTROPY_BYTES)
        try {
            return fromEntropy(entropy)
        } finally {
            entropy.fill(0)
        }
    }

    fun fromEntropy(entropy: ByteArray): String {
        require(entropy.size == ENTROPY_BYTES) { "a 24-word recovery phrase requires 256 bits of entropy" }
        return MnemonicUtils.generateMnemonic(entropy)
    }

    fun isValid(phrase: String): Boolean =
        phrase.split(' ').size == WORD_COUNT &&
            phrase.all { it == ' ' || it in 'a'..'z' } &&
            !phrase.startsWith(' ') &&
            !phrase.endsWith(' ') &&
            !phrase.contains("  ") &&
            MnemonicUtils.validateMnemonic(phrase)
}
