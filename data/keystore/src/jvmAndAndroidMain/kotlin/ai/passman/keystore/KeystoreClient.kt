package ai.passman.keystore

import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.keystore.model.Keystore
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import java.security.Key
import java.security.KeyStore

interface KeystoreClient {
    /**
     * [initialKey], when given, is generated and added before the store is first written, so a new
     * store with one key costs a single PKCS#12 `store()` instead of the
     * create / reload / add-key / store-again round trip — every PKCS#12 store or load pays the
     * full PBE/MAC KDF, seconds apiece on a phone.
     */
    fun createKeyStore(
        keystoreType: KeyStoreType,
        keystorePath: String,
        keystoreName: String,
        keystorePassword: String,
        initialKey: KeystoreKey? = null,
    ): Result<Keystore>
    fun getKeyStoreInfo(keystore: Keystore): Result<KeyStore?>
    fun addKeystoreKey(keystore: Keystore, keyAlias: String, keyPassword: String, algorithm: KeystoreKeyAlgorithm): Result<Boolean>
    fun deleteKeystore(keystore: Keystore): Boolean
    fun deleteKeyStoreKey(keystore: Keystore, keyAlias: String): Boolean
    fun changeKeystorePassword(
        keystorePath: String,
        keystoreName: String,
        keystoreType: KeyStoreType,
        oldPassword: String,
        newPassword: String,
    ): Outcome<Unit>

    /**
     * The account identity store — the one `.pfx` per account that holds the RSA key everything else
     * is wrapped under.
     *
     * These three are separate from [createKeyStore] / [addKeystoreKey] / [changeKeystorePassword]
     * for one reason: they write **low-PBE** PKCS#12 (see [LowPbePkcs12Writer]), which is sound only
     * because the identity store's password is a 256-bit uniformly random value derived from the
     * device keyring. The methods above stay on the JCA writer and the provider's strong defaults,
     * because the keystore-tools UI seals those files with whatever the user typed. Do not merge the
     * two sets.
     *
     * That precondition is no longer prose: every one of them demands an [IdentityStorePassword],
     * whose only production source is `VaultCipher.identityStorePassword`. A caller holding a login
     * password cannot reach these methods at all without naming
     * [IdentityStorePassword.unsafeNotFromKeyring], which is a grep away.
     *
     * Every one of them leaves the file on disk openable whatever happens: they build the replacement
     * beside the original, prove it opens and still holds the same aliases, and only then swap it in
     * with an atomic replace — keeping [identityStoreBackupName] beside it for the one swap that
     * cannot be atomic.
     */
    fun createIdentityKeyStore(
        keystorePath: String,
        keystoreName: String,
        keystorePassword: IdentityStorePassword,
        keyAlias: String,
    ): Outcome<Unit>

    /** Move the identity store from [oldPassword] onto the keyring-derived [newPassword]. */
    fun changeIdentityKeyStorePassword(
        keystorePath: String,
        keystoreName: String,
        oldPassword: String,
        newPassword: IdentityStorePassword,
    ): Outcome<Unit>

    /**
     * Rewrite the identity store at low PBE parameters if it is not already there, keeping [password].
     *
     * A no-op — and a cheap one, no PBE runs — when the file's parameters are already low. This is the
     * one-time upgrade for accounts whose store was created or migrated by the JCA writer.
     */
    fun reencodeIdentityKeyStore(keystorePath: String, keystoreName: String, password: IdentityStorePassword): Outcome<Unit>

    /**
     * Put [identityStoreBackupName] back over a live identity store that is gone or unreadable, if
     * and only if the backup verifies under [password] and holds [expectedAlias]. Returns true when
     * it did.
     *
     * The state this recovers from is narrow and permanent without it: on a filesystem that cannot
     * promise an atomic move, a commit's replace can leave a truncated `.pfx`, and if the immediate
     * restore *also* fails the only intact copy of the account's RSA identity is the backup file. The
     * commit logs its path and gives up; this is what makes the next login finish the job instead of
     * a human with a file manager.
     *
     * [password] is a plain `String`, not an [IdentityStorePassword], because the recovery is a
     * byte-for-byte restore of a file this device already wrote — no PBE parameters are chosen, so
     * there is nothing to downgrade — and because the store being restored may predate the keyring
     * and still be sealed with the login password.
     *
     * [expectedAlias] is the entry the caller is about to look for — in production always
     * [IDENTITY_KEY_ALIAS], which is why that constant lives here. It is a parameter rather than an
     * assumption because the verification used to accept *any* private-key alias while the caller
     * (`JvmKeystoreLifecycle.canOpenKeystore`) went on to demand `passmanMain`: a backup holding only
     * some other alias was published **and then deleted**, after which the caller's probe failed and
     * the one recovery artefact was gone. The contract this proves and the contract the caller checks
     * have to be the same contract.
     *
     * Refuses, and leaves both files exactly as it found them, when: there is no backup; the live
     * store is still a structurally intact PKCS#12 (a store that merely does not open under *this*
     * password is an ordinary wrong-password answer, not damage); the backup does not open under
     * [password]; or it does not hold [expectedAlias] as a private-key entry that unwraps under
     * [password]. A backup that does not verify is never deleted — a stale one from a previous
     * password is still evidence. The backup is deleted only after the *published* store has been
     * re-read and proved to satisfy the same contract.
     *
     * Serialised against [createIdentityKeyStore], [changeIdentityKeyStorePassword] and
     * [reencodeIdentityKeyStore] by the lock at [identityStoreLockName], and re-checks the live store
     * after taking it: a commit that published while this call was waiting means there is nothing to
     * recover, and restoring then would silently revert it.
     */
    fun restoreIdentityKeyStoreFromBackup(
        keystorePath: String,
        keystoreName: String,
        password: String,
        expectedAlias: String,
    ): Boolean

    fun encryptData(publicKey: Key, plainData: String, cipherIv: ByteArray): Outcome<EncryptedData>
    fun encryptFile(filePath: String, newFilePath: String, publicKey: Key, cipherIv: ByteArray): Outcome<EncryptedData>

    fun decryptData(secretKey: Key, cipherData: String, cipherIv: String): Outcome<String>
    fun decryptFile(secretKey: Key, cipherFilePath: String, decryptedFilePath: String, cipherIv: String, keyPassword: String): Outcome<String>

    fun sign(privateKey: Key, plainText: String, passPhrase: String): String?
    fun signFile(filePath: String, privateKey: Key, passPhrase: String): String?
    fun verify(publicKey: Key, data: ByteArray, signature: String): Boolean

    fun unwrapKey(keyStore: KeyStore, alias: String, password: CharArray): Key?

    companion object {
        /**
         * The suffix of the recovery copy an identity-store commit keeps beside the live file.
         *
         * **Deterministic on purpose.** It used to be `File.createTempFile`'s `<name>.<random>.bak`,
         * which meant a stranded backup — a file holding a complete, openable copy of the device's
         * RSA identity — had a name nothing could match. `DirectoryBundler.syncExclusions` is an
         * exact-basename set, so that file was excluded from neither the outbound keystore bundle nor
         * an inbound one: one interrupted commit and the next sync shipped the private key to a peer.
         * One well-known name makes the exclusion exact, makes the file findable by a human, and
         * makes "there is already a backup here" a defined state rather than an accumulating pile.
         *
         * Declared on this interface rather than in `DirectoryBundler` because `data:repo` depends on
         * `data:keystore` and not the other way round; the bundler imports it, so the exclusion cannot
         * drift from the writer.
         */
        const val IDENTITY_STORE_BACKUP_SUFFIX = ".bak"

        /**
         * The suffix of the replacement an identity-store commit builds beside the live file.
         *
         * Must equal `DirectoryBundler.TEMP_FILE_SUFFIX`, which is what actually keeps these out of a
         * sync bundle; `DirectoryBundlerSyncExclusionsTest` asserts the two agree, because the pair of
         * constants is the whole reason the exclusion set is provably complete (see
         * [identityStoreBackupName]).
         */
        const val IDENTITY_STORE_TEMP_SUFFIX = ".tmp"

        /**
         * The suffix of the advisory lock file that serialises identity-store commits and recoveries.
         *
         * Deterministic for the same reason [IDENTITY_STORE_BACKUP_SUFFIX] is: the file is created in
         * `keystore/<user>/`, which is exactly what a keystore sync bundles, and
         * `DirectoryBundler.syncExclusions` is an exact-basename set. Unlike the backup this one holds
         * no bytes at all, so it is not a leak — but it is debris, and an exclusion set that is
         * "everything a commit can leave except this one thing" is not a set anybody can reason about.
         *
         * It is deliberately **never deleted**. Removing a lock file that another process may still
         * hold open unlinks the inode both sides are locking, and the next pair of racers then lock
         * two different files and both proceed — which is the exact failure this lock exists to
         * prevent. A zero-length file per account is the price.
         */
        const val IDENTITY_STORE_LOCK_SUFFIX = ".lock"

        /**
         * The alias every account's identity key pair is written under. Frozen: it is on disk.
         *
         * Declared here because three modules have to agree on it and none of them owns the others:
         * `JvmKeystoreLifecycle` creates the store with it and probes for it,
         * `restoreIdentityKeyStoreFromBackup` verifies a backup against it, and `ToolsModule` resolves
         * the session keys with it. It was three separate `private const val`s until a recovery path
         * verified "some private-key alias" against a caller that required this one; the drift was the
         * bug, so the constant is now single.
         */
        const val IDENTITY_KEY_ALIAS = "passmanMain"

        /** The recovery copy kept beside [keystoreName] during a commit. See [IDENTITY_STORE_BACKUP_SUFFIX]. */
        fun identityStoreBackupName(keystoreName: String): String = "$keystoreName$IDENTITY_STORE_BACKUP_SUFFIX"

        /** The lock file guarding [keystoreName]'s commits and recoveries. See [IDENTITY_STORE_LOCK_SUFFIX]. */
        fun identityStoreLockName(keystoreName: String): String = "$keystoreName$IDENTITY_STORE_LOCK_SUFFIX"

        /**
         * The filename of [userName]'s identity store inside `keystore/<userName>/`.
         *
         * The account's RSA identity: the vault's key material is sealed under it and nothing else
         * holds a copy, so a write that lands on this name and is not an identity-store commit
         * destroys the account.
         *
         * Declared here because three places need to agree on it and, until this was extracted, three
         * places spelled it out independently — `JvmKeystoreLifecycle`, which creates it;
         * `DirectoryBundler.syncExclusions`, which must keep it off the wire; and
         * `LocalKeystoreRepository`, which must refuse to let an ordinary keystore creation or import
         * land on it. That last one is not hypothetical: creating a keystore named after the account
         * used to resolve straight onto this file and truncate it, with no lock and no warning.
         *
         * Same reasoning as [IDENTITY_STORE_BACKUP_SUFFIX] for the placement — `data:repo` depends on
         * `data:keystore` and not the other way round.
         */
        fun identityStoreName(userName: String): String = "$userName.pfx"

        /**
         * Whether [keystoreName] would land on [userName]'s identity store.
         *
         * Compared case-insensitively because the filesystems this ships on decide that, not the
         * comparison: on APFS and NTFS `Alice.pfx` and `alice.pfx` are one file, so a check that only
         * matched the exact spelling would wave through the very write it exists to refuse.
         *
         * It is deliberately **not** a resolution-aware check — it cannot be, at this layer. A name
         * that differs by Unicode normal form still resolves to the same file on those filesystems
         * and still passes here. That is the same weakness `DirectoryBundler.syncExclusions` has, and
         * closing it properly means comparing canonical paths rather than names; this guard covers
         * the case that actually happens, which is a user typing their own account name.
         */
        fun isIdentityStoreName(keystoreName: String, userName: String): Boolean =
            keystoreName.equals(identityStoreName(userName), ignoreCase = true)
    }
}
