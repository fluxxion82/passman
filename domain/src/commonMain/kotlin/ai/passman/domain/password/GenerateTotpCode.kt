package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.totp.TotpConfig
import ai.passman.domain.password.totp.TotpGenerator

/**
 * Turns a stored TOTP seed (raw base32 or otpauth uri) into the code valid right now.
 * Returns null for a seed that does not parse — the caller decides how to surface that.
 */
class GenerateTotpCode(
    private val epochSeconds: () -> Long,
) : Usecase<String, GenerateTotpCode.TotpCode?> {

    data class TotpCode(val code: String, val secondsRemaining: Int, val periodSeconds: Int)

    override suspend fun invoke(param: String): TotpCode? {
        val config = runCatching { TotpConfig.parse(param) }.getOrNull() ?: return null
        val now = epochSeconds()
        return TotpCode(
            code = TotpGenerator.code(config.secret, now, config.periodSeconds, config.digits),
            secondsRemaining = TotpGenerator.secondsRemaining(now, config.periodSeconds),
            periodSeconds = config.periodSeconds,
        )
    }
}
