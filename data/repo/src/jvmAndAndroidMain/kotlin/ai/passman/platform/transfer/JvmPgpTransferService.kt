package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice

/**
 * PGP-bundle push/pull under the same per-device policy as `JvmPasswordTransferService`, shared with
 * it through [ArtifactSyncClient]: this class only names [SyncArtifact.PgpKeys], which carries the
 * `/upload/pgp-keys` route, the `pgp-keys` sync-pull kind and the "pgp bundle" failure label.
 */
class JvmPgpTransferService(
    private val client: ArtifactSyncClient,
) : PgpTransferService {
    override suspend fun transferPgpBundle(
        decryptedBundleBytes: ByteArray,
        fileName: String,
        device: TrustedDevice,
        port: Int,
    ): Outcome<Unit> = client.push(SyncArtifact.PgpKeys, decryptedBundleBytes, fileName, device, port)

    override suspend fun pullPgpBundle(
        device: TrustedDevice,
        port: Int,
    ): Outcome<ByteArray> = client.pull(SyncArtifact.PgpKeys, device, port)
}
