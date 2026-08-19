package ai.passman.platform.repository

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.vault.PortableVaultFormat
import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.encodeToString
import java.io.File

/**
 * The vault half of the receive side: opening a vault-shaped blob of any generation, and reconciling
 * a staged inbound copy against the live vault.
 *
 * Split out of [FileTransferRepository], which keeps the server lifecycle and the handler wiring and
 * calls [openVault] on this object from its upload and sync-pull handlers.
 *
 * @property sessionKey the session's device master key, resolved by the repository.
 * @property legacyKeyHandle resolves the session scope (suspending) and hands back the *lazy*
 *   legacy-key lookup [VaultCipher.decryptVault] consults only for pre-suite-5 bytes. Two stages
 *   because that provider is not a suspending function: resolving the key eagerly here would open
 *   the PKCS#12 identity store on every vault read, which is exactly what its laziness prevents.
 */
internal class VaultReconciler(
    private val passwordDatabaseStorage: PasswordDatabaseStorage,
    private val userPreferences: UserPreferences,
    private val vaultCipher: VaultCipher,
    private val entryIdentity: PasswordEntryIdentity,
    private val tmpDir: String,
    private val sessionKey: suspend () -> VaultSessionKey,
    private val legacyKeyHandle: suspend () -> (() -> CryptoKey?),
    private val portableVaultFormat: PortableVaultFormat? = null,
) {

    suspend fun executeReconcileAction(reconcileAction: ReconcileAction): Outcome<Unit> {
        return when (reconcileAction) {
            ReconcileAction.Delete -> {
                File(tmpDir).listFiles()?.forEach { it.delete() }
                Outcome.Success(Unit)
            }

            else -> runCatching {
                val tmpDirFile = File(tmpDir)
                val user = userPreferences.getUser() as AppUser.LoggedIn
                var failedCount = 0

                tmpDirFile.listFiles()?.forEach { newDb ->
                    if (newDb.name == user.userName.hashCode().toString() && passwordDatabaseStorage.exists(user.userName)) {
                        val result = runCatching {
                            val newJsonString = openVault(newDb.readBytes()).decodeToString()
                            val existing = passwordDatabaseStorage.read(user.userName)

                            // Both sides are stabilised before anything is keyed or written. The
                            // staged file can come from a build that has no uuid field at all, and
                            // taking its rows verbatim would publish a vault whose entries have no
                            // identity — silently discarding the identities the local rows already
                            // carry, and handing the next rename a duplicate. Deriving here reaches
                            // the same values the peer derives for itself.
                            val entries = if (reconcileAction == ReconcileAction.Merge) {
                                val curJsonString = openVault(existing).decodeToString()

                                // VaultJson (lenient on unknown keys): the staged file can come from
                                // a build one field ahead of this one — see VaultJson's KDoc.
                                val curEntries =
                                    entryIdentity.stabilize(VaultJson.decodeFromString<List<PasswordEntry>>(curJsonString))
                                val newEntries =
                                    entryIdentity.stabilize(VaultJson.decodeFromString<List<PasswordEntry>>(newJsonString))

                                // Keyed on uuid, like LocalPasswordRepository.mergePasswordEntries:
                                // on two migrated vaults the uuid is a relabelling of entryName, so
                                // this is the same merge it has always been, and it stops being the
                                // same one only for entries created after the upgrade.
                                //
                                // activity/createdAt are unioned in *both* arms below, not only when
                                // the staged row wins on dateCreated - see mergeActivity's KDoc and
                                // LocalPasswordRepository.mergePasswordEntries's KDoc for why a
                                // winner-arm-only union is broken: it drops the losing side's activity
                                // and createdAt permanently instead of converging on the next sync.
                                val byUuid = curEntries.associateBy { it.uuid }.toMutableMap()
                                for (pass in newEntries) {
                                    val existingEntry = byUuid[pass.uuid]
                                    byUuid[pass.uuid] = when {
                                        existingEntry == null -> pass
                                        pass.dateCreated > existingEntry.dateCreated -> pass.copy(
                                            activity = mergeActivity(existingEntry.activity, pass.activity),
                                            createdAt = minNonZero(existingEntry.createdAt, pass.createdAt),
                                        )
                                        else -> existingEntry.copy(
                                            activity = mergeActivity(existingEntry.activity, pass.activity),
                                            createdAt = minNonZero(existingEntry.createdAt, pass.createdAt),
                                        )
                                    }
                                }
                                byUuid.values.sortedBy { it.entryName.lowercase() }
                                    .mapIndexed { index, entry -> entry.copy(id = (index + 1).toString()) }
                            } else {
                                // Overwrite: the staged rows verbatim, local activity and all. That is
                                // inherent to what Overwrite means - "take theirs" - not a gap this
                                // schema step missed; there is no local row left to union against.
                                entryIdentity.stabilize(VaultJson.decodeFromString<List<PasswordEntry>>(newJsonString))
                            }

                            // A reconcile that converts a legacy vault owes the user the same
                            // downgrade copy a login does — this is the one write path that can
                            // replace an RSA-wrapped vault without ever going through
                            // LocalPasswordRepository.
                            //
                            // Merge aborts if the copy cannot be written. The local vault decrypted
                            // a few lines above, so there is something to lose, and refusing costs
                            // the user only a retry — which is the compatibility policy's rule: no
                            // suite-5 vault replaces a legacy one without `.premigration.v2` beside
                            // it. Overwrite stays best-effort because discarding the local vault is
                            // the entire point of it: it may not decrypt at all, and failing the
                            // action would leave the user unable to take the peer's copy.
                            if (!isSuiteFiveVault(existing)) {
                                runCatching { passwordDatabaseStorage.retainPreMigration(user.userName, existing) }
                                    .onFailure { failure ->
                                        KLogger.e(failure) { "reconcile: could not retain the pre-migration vault" }
                                        if (reconcileAction == ReconcileAction.Merge) throw failure
                                    }
                            }

                            val newData = VaultJson.encodeToString(entries)
                            val session = sessionKey()
                            passwordDatabaseStorage.write(
                                user.userName,
                                portableVaultFormat?.seal(user.userName, newData.toByteArray(), session)
                                    ?: vaultCipher.encryptVault(newData.toByteArray(), session),
                            )

                            newDb.delete()
                        }.onFailure {
                            if (it is CancellationException) throw it
                            KLogger.e(it) { "failed to reconcile staged password database ${newDb.name}" }
                        }
                        if (result.isFailure) failedCount++
                    }
                }
                if (failedCount == 0) {
                    Outcome.Success(Unit)
                } else {
                    Outcome.Error(
                        "Failed to reconcile $failedCount staged password database(s)",
                        TransferFailure.GeneralTransferFailure,
                    )
                }
            }.onFailure {
                if (it is CancellationException) throw it
                KLogger.e(it) { "failed to reconcile password databases" }
            }.getOrElse {
                Outcome.Error("failed to reconcile password databases", TransferFailure.GeneralTransferFailure)
            }
        }
    }

    /**
     * Decrypt a vault-shaped blob — the live vault, or a staged inbound copy — of any generation.
     *
     * The legacy RSA key is resolved lazily and only for pre-suite-5 bytes, so the ordinary path
     * never opens the PKCS#12 identity store. It is resolved through `runCatching` because the
     * definition takes two parameters and fails rather than returning null on a scope login never
     * warmed; either way the answer is "no legacy key", which `decryptVault` reports as a typed
     * failure instead of a crash.
     */
    suspend fun openVault(bytes: ByteArray): ByteArray {
        if (portableVaultFormat?.isPortable(bytes) == true) {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            return portableVaultFormat.open(user.userName, bytes, sessionKey())
        }
        val legacyKey = legacyKeyHandle()
        return vaultCipher.decryptVault(bytes, sessionKey(), legacyKey).plaintext
    }

    /** True for a "PMNV" version-1 suite-5 envelope — the current at-rest vault format. */
    private fun isSuiteFiveVault(bytes: ByteArray): Boolean =
        bytes.size > SUITE_OFFSET &&
            bytes[0] == 'P'.code.toByte() && bytes[1] == 'M'.code.toByte() &&
            bytes[2] == 'N'.code.toByte() && bytes[3] == 'V'.code.toByte() &&
            bytes[SUITE_OFFSET] == SUITE_VAULT

    private companion object {
        /** Mirrors `PasswordVaultCipher`'s header layout; only used to decide "is this already v5?". */
        const val SUITE_OFFSET = 5
        const val SUITE_VAULT: Byte = 5
    }
}
