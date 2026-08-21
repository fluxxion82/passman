package ai.passman.repo.repositories

import ai.passman.cache.KeyCacheManager
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.keystore.JvmKeyStoreClient
import ai.passman.platform.transfer.KeystoreTransferService
import ai.passman.repo.Platform
import ai.passman.repo.di.KEYSTORE_CACHE
import ai.passman.domain.base.DefaultContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module

class LocalKeystoreRepositoryTest {
    private lateinit var localDir: File
    private lateinit var keystoreDir: File
    private lateinit var repository: LocalKeystoreRepository

    private val keystoreName = "test.pfx"
    private val keystorePassword = "keystore-password"
    private val rsaAlias = "rsa-key"
    private val rsaPassword = keystorePassword
    private val aesAlias = "aes-key"
    private val aesPassword = "aes-password"

    private class FakePlatform(private val localPath: File) : Platform() {
        override fun getLocalPath(): String = localPath.absolutePath
    }

    private class FakePreferences(private val userName: String = "alice") : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn(userName, Password("password", "salt"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "keystore-repository-test"
        override suspend fun clear() = Unit
    }

    private class FakeTransferService : KeystoreTransferService {
        override suspend fun transferKeystoreBundle(
            decryptedBundleBytes: ByteArray,
            fileName: String,
            device: TrustedDevice,
            port: Int,
        ): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun pullKeystoreBundle(device: TrustedDevice, port: Int): Outcome<ByteArray> =
            Outcome.Success(ByteArray(0))
    }

    @BeforeTest
    fun setUp() {
        localDir = Files.createTempDirectory("local-keystore-repository-test").toFile()
        keystoreDir = File(localDir, "keystore/alice").apply { mkdirs() }
        val client = JvmKeyStoreClient()
        val keystore = client.createKeyStore(
            KeyStoreType.PKCS12,
            keystoreDir.absolutePath,
            keystoreName,
            keystorePassword,
        ).getOrThrow()
        check(client.addKeystoreKey(keystore, rsaAlias, rsaPassword, KeystoreKeyAlgorithm.RSA).getOrThrow())
        check(client.addKeystoreKey(keystore, aesAlias, aesPassword, KeystoreKeyAlgorithm.AES).getOrThrow())

        startKoin {
            modules(
                module {
                    scope(named("keystoreCacheScope")) {
                        scoped(named(KEYSTORE_CACHE)) { KeyCacheManager() }
                    }
                },
            )
        }
        repository = LocalKeystoreRepository(
            platform = FakePlatform(localDir),
            userPreferences = FakePreferences(),
            keyStoreClient = client,
            coroutinesContextFacade = DefaultContextFacade(),
            keystoreTransferService = FakeTransferService(),
        )
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        localDir.deleteRecursively()
    }

    @Test
    fun decryptText_rejectsWrongKeyPasswordAfterAliasListing() = runBlocking {
        loadAliases()
        val encrypted = encryptRsa("plain text")

        val result = repository.decryptText(
            keystoreDir.absolutePath, keystoreName, rsaAlias, "wrong-password", "salt", encrypted,
        )

        assertIncorrectKeyPassword(rsaAlias, result)
    }

    @Test
    fun updateKeystore_addsTheKeyAlgorithmTheCallerAskedFor() = runBlocking {
        // The chosen algorithm used to be accepted and then thrown away: every key added to an
        // existing keystore came out RSA. Read it back rather than trusting the return value —
        // "no error" was always true here, even when the wrong key type was written.
        repository.updateKeystore(
            keystorePath = keystoreDir.absolutePath,
            keystoreName = keystoreName,
            keystorePassword = keystorePassword,
            newKeyAlias = "added-aes",
            newKeyPassword = "added-password",
            newKeyAlgo = KeystoreKeyAlgorithm.AES,
        )

        // getKeystoreKey serves the alias cache, and only a load+list fills it — updateKeystore
        // does not refresh it, so a screen that added a key without re-listing would not see it.
        loadAliases()

        val added = repository.getKeystoreKey(keystoreDir.absolutePath, keystoreName, "added-aes")
        assertEquals(KeystoreKeyAlgorithm.AES, added.keyAlgorithm)
    }

    @Test
    fun updateKeystore_stillAddsAnRsaKeyWhenThatIsWhatWasAsked() = runBlocking {
        repository.updateKeystore(
            keystorePath = keystoreDir.absolutePath,
            keystoreName = keystoreName,
            keystorePassword = keystorePassword,
            newKeyAlias = "added-rsa",
            newKeyPassword = "added-password",
            newKeyAlgo = KeystoreKeyAlgorithm.RSA,
        )

        loadAliases()

        val added = repository.getKeystoreKey(keystoreDir.absolutePath, keystoreName, "added-rsa")
        assertEquals(KeystoreKeyAlgorithm.RSA, added.keyAlgorithm)
    }

    @Test
    fun createKeyStore_returnsTheOnDiskNameAndASingleSeparatorPath() = runBlocking {
        val outcome = repository.createKeyStore(
            ai.passman.domain.keystore.CreateKeyStore.CreateRequest(
                keystoreName = "fresh",
                keystorePassword = "fresh-password",
                keyAlgorithm = KeystoreKeyAlgorithm.RSA,
                keyAlias = "main",
                aliasPassword = "fresh-password",
                keystoreType = KeyStoreType.PKCS12,
            ),
        )

        val info = assertIs<Outcome.Success<ai.passman.domain.keystore.model.KeyStoreInfo>>(outcome).value
        // The name carries the extension (getAllKeystores lists file names WITH it) and the path
        // has no double separator (keystoreDir already ends in one).
        assertEquals("fresh.pfx", info.name)
        assertTrue(
            !info.path.contains("${File.separator}${File.separator}"),
            "path must not contain a doubled separator: ${info.path}",
        )
        assertTrue(File(info.path, info.name).isFile, "the reported path+name must locate the file")
        assertTrue(
            repository.getAllKeystores().any { it.name == info.name && it.path == info.path },
            "createKeyStore and getAllKeystores must agree on name and path",
        )
    }

    @Test
    fun getAllKeystores_excludesTheCurrentProfilesInternalIdentityStore() = runBlocking {
        File(keystoreDir, "alice.pfx").writeBytes(byteArrayOf(1))
        File(keystoreDir, "alice.recovery.p12").writeBytes(byteArrayOf(1))

        val stores = repository.getAllKeystores()

        assertEquals(listOf(keystoreName), stores.map { it.name })
    }

    @Test
    fun decryptText_rejectsBlankKeyPasswordAfterAliasListing() = runBlocking {
        loadAliases()
        val encrypted = encryptRsa("plain text")

        val result = repository.decryptText(
            keystoreDir.absolutePath, keystoreName, rsaAlias, "", "salt", encrypted,
        )

        assertIncorrectKeyPassword(rsaAlias, result)
    }

    @Test
    fun decryptText_roundTripsWithCorrectKeyPassword() = runBlocking {
        loadAliases()
        val encrypted = encryptRsa("plain text")

        val result = repository.decryptText(
            keystoreDir.absolutePath, keystoreName, rsaAlias, rsaPassword, "salt", encrypted,
        )

        assertEquals("plain text", assertIs<Outcome.Success<String>>(result).value)
    }

    @Test
    fun signText_requiresCorrectKeyPasswordAndProducesVerifiableSignature() = runBlocking {
        loadAliases()

        assertIncorrectKeyPassword(rsaAlias,
            repository.signText(keystoreDir.absolutePath, keystoreName, rsaAlias, "plain text", "wrong-password"),
        )
        assertIncorrectKeyPassword(rsaAlias,
            repository.signText(keystoreDir.absolutePath, keystoreName, rsaAlias, "plain text", ""),
        )
        val signature = assertIs<Outcome.Success<String>>(
            repository.signText(keystoreDir.absolutePath, keystoreName, rsaAlias, "plain text", rsaPassword),
        ).value

        assertTrue(
            assertIs<Outcome.Success<Boolean>>(
                repository.verifySignature(keystoreDir.absolutePath, keystoreName, rsaAlias, "plain text", signature),
            ).value,
        )
    }

    @Test
    fun encryptText_rsaSucceedsWithBlankKeyPassword() = runBlocking<Unit> {
        loadAliases()

        val result = repository.encryptText(
            keystoreDir.absolutePath, keystoreName, rsaAlias, "", "salt", "plain text",
        )

        assertIs<Outcome.Success<*>>(result)
    }

    @Test
    fun aesAlias_isListedAndRequiresCorrectPasswordForEncryptAndDecrypt() = runBlocking {
        val aliases = loadAliases()
        assertEquals(KeystoreKeyAlgorithm.AES, aliases.single { it.keyAlias == aesAlias }.keyAlgorithm)

        assertIncorrectKeyPassword(aesAlias,
            repository.encryptText(keystoreDir.absolutePath, keystoreName, aesAlias, "wrong-password", "salt", "plain text"),
        )
        val encrypted = assertIs<Outcome.Success<ai.passman.domain.crypto.model.EncryptedData>>(
            repository.encryptText(keystoreDir.absolutePath, keystoreName, aesAlias, aesPassword, "salt", "plain text"),
        ).value.ciphertextOrPath
        val decrypted = repository.decryptText(
            keystoreDir.absolutePath, keystoreName, aesAlias, aesPassword, "salt", encrypted,
        )

        assertEquals("plain text", assertIs<Outcome.Success<String>>(decrypted).value)
    }

    @Test
    fun getKeystoreKey_returnsCachedAlgorithm() = runBlocking {
        loadAliases()

        val rsaKey = repository.getKeystoreKey(keystoreDir.absolutePath, keystoreName, rsaAlias)
        val aesKey = repository.getKeystoreKey(keystoreDir.absolutePath, keystoreName, aesAlias)

        assertEquals(KeystoreKeyAlgorithm.RSA, rsaKey.keyAlgorithm)
        assertEquals(KeystoreKeyAlgorithm.AES, aesKey.keyAlgorithm)
    }

    /**
     * A keystore named after the account is refused, and the identity store is left alone.
     *
     * `createKeyStore` appends `.pfx` unless the requested name already ends in it, and the identity
     * store is `<username>.pfx` in the same directory. So for the account `alice`, a keystore called
     * `alice` used to resolve to `keystore/alice/alice.pfx` — the account's RSA identity, which the
     * vault's key material is sealed under and of which nothing else holds a copy — and
     * `JvmKeyStoreClient.createKeyStore` published it with a truncating `outputStream()`, taking no
     * `IdentityStoreLock`. Two words in a "new keystore" form destroyed the account.
     *
     * Refused by **name** rather than ordered by lock, deliberately. The artifact-directory lock this
     * branch adds makes the overwrite orderly; it does not make it survivable. Nothing legitimate
     * wants to write that name except an identity-store commit.
     *
     * Asserted through the repository rather than by recomputing the filename here: the collision is
     * a property of the app's own name derivation, and a test that spelled `alice.pfx` itself would
     * only be checking a copy of the rule it is supposed to be testing.
     */
    @Test
    fun createKeyStore_refusesTheAccountsOwnNameAndLeavesTheIdentityStoreIntact() = runBlocking {
        val identityStore = File(keystoreDir, "alice.pfx")
        val identityBytes = ByteArray(64) { 0x7F }
        identityStore.writeBytes(identityBytes)

        val outcome = repository.createKeyStore(
            ai.passman.domain.keystore.CreateKeyStore.CreateRequest(
                // The account name, not a path and not a filename. Exactly what the UI field takes.
                keystoreName = "alice",
                keystorePassword = "collision-password",
                keyAlgorithm = KeystoreKeyAlgorithm.RSA,
                keyAlias = "main",
                aliasPassword = "collision-password",
                keystoreType = KeyStoreType.PKCS12,
            ),
        )

        assertIs<Outcome.Error>(outcome, "creating a keystore at the identity store's name must fail")
        assertContentEquals(
            identityBytes,
            identityStore.readBytes(),
            "and must not have touched the identity store on its way to failing",
        )
    }

    /**
     * A keystore name is not a path, and treating it as one destroyed *another account's* identity.
     *
     * The requested name is concatenated straight into a path — `File(folder, keystoreName)` — and
     * the guard that came before this one compared whole strings. So `../bob/bob` was a keystore name
     * that resolved into Bob's directory, matched nothing, and truncated `bob.pfx` with a fresh
     * store: one user destroying another user's RSA identity from the new-keystore form, while
     * holding only their own directory's lock. `./alice` reached Alice's own identity store the same
     * way.
     *
     * The guard now resolves the destination with the filesystem and requires it to be a direct child
     * of the account's keystore directory, which is why every spelling below is refused by the same
     * check rather than by an enumeration of the tricks.
     */
    @Test
    fun createKeyStore_refusesANameThatIsReallyAPath() = runBlocking {
        val bobDir = File(localDir, "keystore${File.separator}bob").apply { mkdirs() }
        val bobIdentity = File(bobDir, "bob.pfx")
        val bobBytes = ByteArray(64) { 0x5A }
        bobIdentity.writeBytes(bobBytes)
        val aliceIdentity = File(keystoreDir, "alice.pfx")
        val aliceBytes = ByteArray(64) { 0x7F }
        aliceIdentity.writeBytes(aliceBytes)

        listOf("../bob/bob", "./alice", "alice/../alice", "../bob/bob.pfx").forEach { typed ->
            val outcome = repository.createKeyStore(
                ai.passman.domain.keystore.CreateKeyStore.CreateRequest(
                    keystoreName = typed,
                    keystorePassword = "traversal-password",
                    keyAlgorithm = KeystoreKeyAlgorithm.RSA,
                    keyAlias = "main",
                    aliasPassword = "traversal-password",
                    keystoreType = KeyStoreType.PKCS12,
                ),
            )
            assertIs<Outcome.Error>(outcome, "\"$typed\" is a path, not a keystore name, and must be refused")
        }

        assertContentEquals(bobBytes, bobIdentity.readBytes(), "another account's identity must be untouched")
        assertContentEquals(aliceBytes, aliceIdentity.readBytes(), "and so must this account's")
    }

    /**
     * The Unicode bypass, which a name comparison could not see.
     *
     * For the account `café` spelled NFC, a keystore named `café` spelled NFD is a different Kotlin
     * string but the same file on APFS and NTFS — so a guard that folded only case waved it through
     * and `createKeyStore` truncated the identity store. Resolving the destination through the
     * filesystem is what closes it: `getCanonicalPath` returns an existing file's on-disk spelling,
     * so both forms canonicalise onto the same path.
     *
     * The identity store has to exist for that resolution to happen, which is exactly the case worth
     * guarding — if it does not exist there is nothing to destroy. Both spellings are written with
     * escapes so an editor cannot normalise the source and leave this comparing a string to itself.
     */
    @Test
    fun createKeyStore_refusesADecomposedSpellingOfTheAccountsOwnName() = runBlocking {
        val nfc = "caf\u00E9"
        val nfd = "cafe\u0301"
        check(nfc.length + 1 == nfd.length) { "precondition: two spellings of one name" }

        val accountDir = File(localDir, "keystore${File.separator}$nfc").apply { mkdirs() }
        val identity = File(accountDir, "$nfc.pfx")
        val identityBytes = ByteArray(64) { 0x3C }
        identity.writeBytes(identityBytes)
        check(File(accountDir, "$nfd.pfx").exists()) {
            "precondition: this filesystem resolves both normal forms to one file"
        }

        val accented = LocalKeystoreRepository(
            platform = FakePlatform(localDir),
            userPreferences = FakePreferences(nfc),
            keyStoreClient = JvmKeyStoreClient(),
            coroutinesContextFacade = DefaultContextFacade(),
            keystoreTransferService = FakeTransferService(),
        )

        val outcome = accented.createKeyStore(
            ai.passman.domain.keystore.CreateKeyStore.CreateRequest(
                keystoreName = nfd,
                keystorePassword = "nfd-password",
                keyAlgorithm = KeystoreKeyAlgorithm.RSA,
                keyAlias = "main",
                aliasPassword = "nfd-password",
                keystoreType = KeyStoreType.PKCS12,
            ),
        )

        assertIs<Outcome.Error>(outcome, "an NFD spelling of the account name resolves onto the identity store")
        assertContentEquals(identityBytes, identity.readBytes(), "which must therefore be untouched")
    }

    /**
     * Import refuses a trailing-dot spelling too.
     *
     * `unbundle` trims trailing dots and spaces before matching an inbound entry, because Windows
     * folds `alice.pfx.` onto `alice.pfx`. Import keeps the source's own filename, so the same
     * spelling arrives by a different door; the guard trims the same way rather than leaving the two
     * comparisons to disagree about what names the identity store.
     */
    @Test
    fun importKeystoreFile_refusesATrailingDotSpellingOfTheIdentityStore() = runBlocking {
        val identity = File(keystoreDir, "alice.pfx")
        val identityBytes = ByteArray(64) { 0x7F }
        identity.writeBytes(identityBytes)
        val incoming = File(localDir, "alice.pfx.").apply { writeBytes(ByteArray(32) { 0x2A }) }

        val outcome = repository.importKeystoreFile(incoming.absolutePath)

        assertIs<Outcome.Error>(outcome, "a trailing-dot spelling names the identity store on Windows")
        assertContentEquals(identityBytes, identity.readBytes())
    }

    /**
     * Whatever the user types, the result is never the identity store.
     *
     * Stated as the invariant rather than as "these spellings are refused", because the two are not
     * the same and only the invariant is what matters. `ALICE.pfx` is refused: it already ends in
     * `.pfx`, so it is taken as the filename and folds onto `alice.pfx` — which the guard has to
     * catch case-insensitively, since APFS and NTFS resolve both to one file. `Alice.PFX` is
     * *accepted*, because the extension check is case-sensitive and appends, producing
     * `Alice.PFX.pfx` — an odd name, but a different file, so nothing is destroyed.
     *
     * Asserting refusal for that second case would have been asserting a rule the app does not have
     * and does not need. Left as an observation rather than "fixed": making the extension check
     * case-insensitive would stop `getAllKeystores` from listing the result, since it filters on a
     * case-sensitive extension, so a user would create a keystore and not see it.
     */
    @Test
    fun createKeyStore_neverLandsOnTheIdentityStoreWhateverTheUserTypes() = runBlocking {
        val identityStore = File(keystoreDir, "alice.pfx")
        val identityBytes = ByteArray(64) { 0x7F }
        identityStore.writeBytes(identityBytes)

        listOf("alice", "alice.pfx", "ALICE.pfx", "Alice.PFX").forEach { typed ->
            val outcome = repository.createKeyStore(
                ai.passman.domain.keystore.CreateKeyStore.CreateRequest(
                    keystoreName = typed,
                    keystorePassword = "collision-password",
                    keyAlgorithm = KeystoreKeyAlgorithm.RSA,
                    keyAlias = "main",
                    aliasPassword = "collision-password",
                    keystoreType = KeyStoreType.PKCS12,
                ),
            )

            if (outcome is Outcome.Success<*>) {
                val info = outcome.value as ai.passman.domain.keystore.model.KeyStoreInfo
                assertTrue(
                    !File(info.path, info.name).absolutePath
                        .equals(identityStore.absolutePath, ignoreCase = true),
                    "\"$typed\" was accepted, so it must not have resolved to the identity store",
                )
            }
            assertContentEquals(
                identityBytes,
                identityStore.readBytes(),
                "\"$typed\" must leave the identity store byte for byte as it was",
            )
        }
    }

    /**
     * Import keeps the source's own filename, so a file called `<user>.pfx` used to land on the
     * identity store and be copied over it with `REPLACE_EXISTING`.
     *
     * Same refusal, same reason. This is the door the plan left open when it deferred
     * "local import can destroy what sync no longer can" — for this one file, it no longer can.
     */
    @Test
    fun importKeystoreFile_refusesToLandOnTheIdentityStore() = runBlocking {
        val identityStore = File(keystoreDir, "alice.pfx")
        val identityBytes = ByteArray(64) { 0x7F }
        identityStore.writeBytes(identityBytes)
        val incoming = File(localDir, "alice.pfx").apply { writeBytes(ByteArray(32) { 0x2A }) }

        val outcome = repository.importKeystoreFile(incoming.absolutePath)

        assertIs<Outcome.Error>(outcome, "importing a file named after the identity store must fail")
        assertContentEquals(
            identityBytes,
            identityStore.readBytes(),
            "and must leave the identity store exactly as it was",
        )
    }

    private suspend fun loadAliases() =
        repository.loadKeystore(keystoreDir.absolutePath, keystoreName).also { check(it != null) }.let {
            assertIs<Outcome.Success<List<ai.passman.domain.keystore.model.KeystoreKey>>>(
                repository.getAliases(keystoreDir.absolutePath, keystoreName, keystorePassword),
            ).value
        }

    private suspend fun encryptRsa(plaintext: String): String =
        assertIs<Outcome.Success<ai.passman.domain.crypto.model.EncryptedData>>(
            repository.encryptText(keystoreDir.absolutePath, keystoreName, rsaAlias, "", "salt", plaintext),
        ).value.ciphertextOrPath

    private fun assertIncorrectKeyPassword(alias: String, outcome: Outcome<*>) {
        val error = assertIs<Outcome.Error>(outcome)
        assertEquals("Incorrect key password for '$alias'", error.message)
    }
}
