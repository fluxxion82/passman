package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice

/**
 * Keystore-bundle push/pull under the same per-device policy as `JvmPasswordTransferService`, shared
 * with it through [ArtifactSyncClient]: this class only names [SyncArtifact.Keystore], which carries
 * the `/upload/keystore` route, the `keystore` sync-pull kind and the "keystore bundle" failure label.
 */
class JvmKeystoreTransferService(
    private val client: ArtifactSyncClient,
) : KeystoreTransferService {
    override suspend fun transferKeystoreBundle(
        decryptedBundleBytes: ByteArray,
        fileName: String,
        device: TrustedDevice,
        port: Int,
    ): Outcome<Unit> = client.push(SyncArtifact.Keystore, decryptedBundleBytes, fileName, device, port)

    override suspend fun pullKeystoreBundle(
        device: TrustedDevice,
        port: Int,
    ): Outcome<ByteArray> = client.pull(SyncArtifact.Keystore, device, port)
}
