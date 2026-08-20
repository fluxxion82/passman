package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice

/**
 * Push/pull of the password database. The per-[ai.passman.domain.connectivity.model.PairingSecurity]
 * dispatch — legacy wire-key fetch, stored-keys-only signed hybrid, refusal of a pairing awaiting
 * re-verification — lives in [ArtifactSyncClient] and is shared with the PGP and keystore services;
 * this class only names the artifact whose route, kind string and failure labels it carries.
 */
class JvmPasswordTransferService(
    private val client: ArtifactSyncClient,
) : PasswordTransferService {
    override suspend fun transferDatabaseBytes(
        decryptedDatabaseBytes: ByteArray,
        fileName: String,
        hostName: String,
        port: Int,
    ): Outcome<Unit> = client.push(SyncArtifact.Passwords, decryptedDatabaseBytes, fileName, hostName, port)

    override suspend fun transferDatabaseBytes(
        decryptedDatabaseBytes: ByteArray,
        fileName: String,
        device: TrustedDevice,
        port: Int,
    ): Outcome<Unit> = client.push(SyncArtifact.Passwords, decryptedDatabaseBytes, fileName, device, port)

    override suspend fun pullDatabase(
        device: TrustedDevice,
        port: Int,
    ): Outcome<ByteArray> = client.pull(SyncArtifact.Passwords, device, port)
}
