package ai.passman.platform.service

import ai.passman.pgp.service.PgpClient

class JvmPgpKeyRingService(private val pgpClient: PgpClient) : PgpKeyRingService {
    override suspend fun createKeyRings(userId: String, password: String, keyDirectory: String): Result<Unit> =
        pgpClient.createKeyRings(
            userId = userId,
            password = password,
            keyDirectory = keyDirectory,
            secretKeyRingFilename = PgpClient.DEFAULT_SECRET_RING_FILENAME,
            publicKeyRingFilename = PgpClient.DEFAULT_PUBLIC_RING_FILENAME,
            // This service exists for the signup path, whose passphrase is always generated
            // (`SignUpUser` mints it with GeneratePassword.PROVISIONED_SECRET).
            s2kCount = PgpClient.PROVISIONED_RING_S2K_COUNT,
        )
}
