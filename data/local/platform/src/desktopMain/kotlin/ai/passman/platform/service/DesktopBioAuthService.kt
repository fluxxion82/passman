package ai.passman.platform.service

internal class DesktopBioAuthService : BioAuthService {
    override suspend fun authenticate(hardwareKeySeed: ByteArray?): BioAuthService.Result =
        BioAuthService.Result.Unavailable
}
