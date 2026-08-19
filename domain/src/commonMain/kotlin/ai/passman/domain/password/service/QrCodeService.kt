package ai.passman.domain.password.service

/**
 * Platform QR decoding — a service, not a repository: the image is user-supplied input, never
 * app-owned state. Kept payload-agnostic so future QR uses (pairing identity exchange) share it;
 * what a payload *means* is the calling use case's business.
 */
interface QrCodeService {
    /**
     * "The platform could not read this file as an image at all" and "a readable image with no
     * QR in it" need different user messages — desktop pickers accept any file, and photo
     * libraries hold formats (HEIC, WebP) some platforms cannot load.
     */
    sealed class DecodeResult {
        data class Payload(val text: String) : DecodeResult()
        data object NoQrFound : DecodeResult()
        data object UnreadableImage : DecodeResult()
    }

    suspend fun decodeImageFile(path: String): DecodeResult
}
