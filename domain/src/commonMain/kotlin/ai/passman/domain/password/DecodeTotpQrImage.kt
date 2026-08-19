package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.service.QrCodeService
import ai.passman.domain.password.totp.TotpConfig

/**
 * Reads a TOTP seed out of a picked QR image. The outcomes are deliberately distinct —
 * "couldn't read that file", "no QR in that image", and "a QR, but not a TOTP setup code"
 * need different user messages.
 */
class DecodeTotpQrImage(
    private val qrCodeService: QrCodeService,
) : Usecase<String, DecodeTotpQrImage.Result> {

    sealed class Result {
        data class Seed(val seed: String) : Result()
        data object NoQrFound : Result()
        data object NotTotp : Result()
        data object UnreadableImage : Result()
    }

    override suspend fun invoke(param: String): Result {
        val payload = when (val decoded = qrCodeService.decodeImageFile(param)) {
            is QrCodeService.DecodeResult.Payload -> decoded.text
            QrCodeService.DecodeResult.NoQrFound -> return Result.NoQrFound
            QrCodeService.DecodeResult.UnreadableImage -> return Result.UnreadableImage
        }
        val seed = TotpConfig.normalizeSeed(payload) ?: return Result.NotTotp
        return Result.Seed(seed)
    }
}
