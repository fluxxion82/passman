package ai.passman.repo.repositories

import ai.passman.cache.KeyCacheManager
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

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("password", "salt"))
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
            hostName: String,
            port: Int,
        ): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun pullKeystoreBundle(hostName: String, port: Int): Outcome<ByteArray> =
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
