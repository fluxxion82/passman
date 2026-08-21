package ai.passman.platform.service

import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.keystore.KeystoreClient
import ai.passman.keystore.model.Keystore
import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import java.io.File

/**
 * The one key every account's identity store holds.
 *
 * Aliased from `data:keystore` rather than spelled out, so that the alias this file creates the store
 * with, the alias it probes for below, the alias `restoreIdentityKeyStoreFromBackup` verifies a backup
 * against, and the alias `ToolsModule` resolves the session keys with are all one string. They were
 * four separate literals, and the recovery path's disagreement with the probe below was the bug.
 */
private const val IDENTITY_KEY_ALIAS = KeystoreClient.IDENTITY_KEY_ALIAS

class JvmKeystoreLifecycle(private val keystoreClient: KeystoreClient) : KeystoreLifecycle {
    /**
     * The identity store is written through the low-PBE writer rather than through
     * `createKeyStore` + `addKeystoreKey`, which are the keystore-tools paths and keep the JCA
     * writer's strong defaults. Signup's [password] is already the keyring-derived store password —
     * `LocalUserRepository.bootstrapAccount` mints the keyring before it gets here — which is the
     * precondition the low iteration count depends on.
     */
    override suspend fun createKeystoreForUser(username: String, keystoreDir: String, password: IdentityStorePassword): Result<Unit> =
        when (
            val outcome = keystoreClient.createIdentityKeyStore(
                keystoreName = keystoreFileName(username),
                keystorePath = accountDirectory(username, keystoreDir),
                keystorePassword = password,
                keyAlias = IDENTITY_KEY_ALIAS,
            )
        ) {
            is Outcome.Success -> Result.success(Unit)
            is Outcome.Error -> Result.failure(IllegalStateException(outcome.message))
        }

    /**
     * The migration write. [newPassword] is always the keyring-derived store password here — the only
     * caller is `LocalUserRepository.resolveIdentityStorePassword`, moving a pre-keyring store off the
     * login password — so the replacement is written at low PBE parameters.
     */
    override suspend fun changeKeystorePassword(
        username: String,
        keystoreDir: String,
        oldPassword: String,
        newPassword: IdentityStorePassword,
    ): Outcome<Unit> = keystoreClient.changeIdentityKeyStorePassword(
        // Must match the name used at creation ("$username.pfx"); passing bare
        // `username` made the load miss the file and silently no-op the change.
        keystoreName = keystoreFileName(username),
        keystorePath = accountDirectory(username, keystoreDir),
        oldPassword = oldPassword,
        newPassword = newPassword,
    )

    override suspend fun reencodeIdentityStoreIfLegacy(
        username: String,
        keystoreDir: String,
        password: IdentityStorePassword,
    ): Outcome<Unit> = keystoreClient.reencodeIdentityKeyStore(
        keystoreName = keystoreFileName(username),
        keystorePath = accountDirectory(username, keystoreDir),
        password = password,
    )

    /**
     * Deliberately probes the *private key*, not just the store.
     *
     * PKCS#12 protects the file's integrity MAC and each key bag separately. Loading the store proves
     * only the MAC password; `unwrapKey` is what the session-key resolution in `ToolsModule` actually
     * performs, so this asks the same question the caller is about to ask for real. A store whose MAC
     * opens but whose key bag does not would otherwise pass the probe and fail the login.
     *
     * ## The recovery seam
     *
     * A `false` here is where a crashed commit's backup gets its one chance. This is the narrowest
     * correct place for it: `LocalUserRepository.resolveIdentityStorePassword` calls this before it
     * touches anything, so a store left truncated by a failed replace *and* a failed restore is
     * noticed while both candidate passwords are still in play — the migration write's backup is under
     * the login password and the re-encode's is under the derived one, and this is the only point that
     * tries both. Everything later (`warmIdentityKeys`, and the re-encode itself) already assumes the
     * store opens, and a login that has failed does not reach them.
     *
     * `restoreIdentityKeyStoreFromBackup` is the one that decides, and it refuses unless the live
     * store is structurally unreadable and the backup verifies under this exact password, so an
     * ordinary wrong-password `false` — which this call makes constantly, by design — changes nothing
     * on disk.
     */
    override suspend fun canOpenKeystore(username: String, keystoreDir: String, password: String): Boolean {
        if (probeKeystore(username, keystoreDir, password)) return true
        val restored = runCatching {
            keystoreClient.restoreIdentityKeyStoreFromBackup(
                keystorePath = accountDirectory(username, keystoreDir),
                keystoreName = keystoreFileName(username),
                password = password,
                // The same alias `probeKeystore` demands below, which is the point: a backup that
                // verifies under a *different* alias is not a recovery for this caller, and accepting
                // one used to publish it and delete it before the probe could disagree.
                expectedAlias = IDENTITY_KEY_ALIAS,
            )
        }.getOrElse {
            KLogger.e(it) { "canOpenKeystore: identity store recovery threw for $username (non-fatal)" }
            false
        }
        return restored && probeKeystore(username, keystoreDir, password)
    }

    private fun probeKeystore(username: String, keystoreDir: String, password: String): Boolean =
        runCatching {
            val descriptor = Keystore(
                path = accountDirectory(username, keystoreDir),
                name = keystoreFileName(username),
                password = password,
            )
            val keyStore = keystoreClient.getKeyStoreInfo(descriptor).getOrNull() ?: return false
            keystoreClient.unwrapKey(keyStore, IDENTITY_KEY_ALIAS, password.toCharArray()) != null
        }.getOrElse {
            // A wrong password is an expected answer here, not an error worth a stack trace.
            KLogger.d { "canOpenKeystore: identity store did not open for $username" }
            false
        }

    override suspend fun identityStoreExists(username: String, keystoreDir: String): Boolean =
        File(accountDirectory(username, keystoreDir), keystoreFileName(username)).isFile

    override suspend fun deleteKeystoreForUser(username: String, keystoreDir: String): Boolean {
        val directory = File(accountDirectory(username, keystoreDir))
        val removed = File(directory, keystoreFileName(username)).delete()
        // The identity store's own artefacts go with it. The lock file is normally never deleted —
        // unlinking one another process holds open leaves the two of them locking different inodes —
        // but this call destroys the very store it guards, so there is nothing left for a survivor of
        // that race to corrupt, and leaving it would keep the account directory non-empty and defeat
        // the rollback below. Deleting the store and keeping its lock is the wrong half to keep.
        File(directory, KeystoreClient.identityStoreLockName(keystoreFileName(username))).delete()
        // A stranded `.bak` is *not* removed here: it is the only intact copy of an RSA identity some
        // earlier commit could not publish, and a signup rollback has no business deciding that. It
        // will keep the directory below, which is the same conservative answer PQ key files get.
        // `delete()` on a directory only succeeds when it is empty, which is exactly the condition we
        // want: a rollback must not remove PQ key files belonging to an account it did not create.
        directory.delete()
        return removed
    }

    private fun keystoreFileName(username: String): String = KeystoreClient.identityStoreName(username)

    private fun accountDirectory(username: String, keystoreDir: String): String = "$keystoreDir$username"
}
