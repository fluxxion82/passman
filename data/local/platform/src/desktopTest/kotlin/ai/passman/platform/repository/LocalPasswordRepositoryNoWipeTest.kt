package ai.passman.platform.repository

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.transfer.PasswordTransferService
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.AddPassword
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * Regression tests for C5: a vault that cannot be read (bad key / corruption / tampering) must
 * NEVER be overwritten. The old code reset it to an empty encrypted DB and, on a second path,
 * coerced unparseable plaintext to an empty list that mutations then persisted — either way the
 * user's data was silently destroyed.
 *
 * The cipher under these tests is the real [PasswordVaultCipher] with a fake [CryptoService] behind
 * its *legacy* branch, so the stored bytes are pre-suite-5 envelopes and every read here takes the
 * migration path — which is exactly where the guard now matters most.
 */
class LocalPasswordRepositoryNoWipeTest {

    private val user = "alice"
    private val dummyKey = CryptoKey(SecretKeySpec(ByteArray(16) { 1 }, "AES"))
    private lateinit var sessionKey: VaultSessionKey

    // Identity crypto behind the legacy branch: stored bytes == plaintext. `failDecrypt` simulates a
    // wrong key / corruption at the cipher layer; otherwise the read fails at JSON parsing for
    // non-JSON stored bytes.
    private class FakeCrypto(var failDecrypt: Boolean = false) : CryptoService {
        override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray = plain
        override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray {
            if (failDecrypt) throw IllegalStateException("simulated decrypt failure")
            return cipher
        }
    }

    private class FakeStorage(initial: ByteArray) : PasswordDatabaseStorage {
        var bytes: ByteArray = initial
        var writeCount: Int = 0
        private var preMigration: ByteArray? = null
        override fun exists(username: String): Boolean = true
        override fun create(username: String, initialEncryptedBytes: ByteArray) { bytes = initialEncryptedBytes }
        override fun delete(username: String) = error("no test reaches delete")
        override fun read(username: String): ByteArray = bytes
        override fun write(username: String, encryptedBytes: ByteArray) {
            writeCount++
            bytes = encryptedBytes
        }
        override fun retainPreMigration(username: String, ciphertext: ByteArray): Boolean {
            if (preMigration != null) return false
            preMigration = ciphertext
            return true
        }
        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean {
            if (!bytes.contentEquals(expected)) return false
            write(username, replacement)
            return true
        }
    }

    private class FakePrefs : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("h", "s"))
        override suspend fun upsert(user: AppUser) {}
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) {}
        override suspend fun getSessionId(): String = "test-session"
        override suspend fun clear() {}
    }

    private class FakeFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }

    private class FakeTransfer(private val pullBytes: ByteArray = ByteArray(0)) : PasswordTransferService {
        override suspend fun transferDatabaseBytes(decryptedDatabaseBytes: ByteArray, fileName: String, hostName: String, port: Int) = Outcome.Success(Unit)
        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            device: TrustedDevice,
            port: Int,
        ) = Outcome.Success(Unit)
        override suspend fun pullDatabase(device: TrustedDevice, port: Int) = Outcome.Success(pullBytes)
    }

    @BeforeTest
    fun setUp() {
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                        scoped(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { dummyKey }
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { dummyKey }
                    }
                }
            )
        }
        sessionKey = PasswordVaultCipher(FakeCrypto()).createSession("a session password").sessionKey
        runBlocking {
            KoinPlatform.getKoin()
                .getOrCreateScope("session-${FakePrefs().getSessionId()}", named("sessionScope"))
                .get<VaultSession>(named(VAULT_SESSION_HANDLE))
                .bind(sessionKey)
        }
    }

    @AfterTest
    fun tearDown() = stopKoin()

    private fun repo(
        storage: FakeStorage,
        crypto: FakeCrypto,
        transferService: PasswordTransferService = FakeTransfer(),
    ) = LocalPasswordRepository(
        userPreferences = FakePrefs(),
        coroutinesContextFacade = FakeFacade(),
        vaultCipher = PasswordVaultCipher(crypto),
        storage = storage,
        transferService = transferService,
        entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
    )

    @Test
    fun getEntries_onUnparseablePlaintext_doesNotOverwriteVault() = runBlocking {
        val corrupt = "this is not valid json".encodeToByteArray()
        val storage = FakeStorage(corrupt)
        val result = repo(storage, FakeCrypto()).getPasswordEntries()

        assertEquals(emptyList(), result, "unreadable DB shows empty for display")
        assertEquals(0, storage.writeCount, "must NOT write over an unreadable vault")
        assertContentEquals(corrupt, storage.bytes, "original ciphertext preserved for recovery")
    }

    @Test
    fun getEntries_onDecryptFailure_doesNotOverwriteVault() = runBlocking {
        val ciphertext = "opaque".encodeToByteArray()
        val storage = FakeStorage(ciphertext)
        val result = repo(storage, FakeCrypto(failDecrypt = true)).getPasswordEntries()

        assertEquals(emptyList(), result)
        assertEquals(0, storage.writeCount)
        assertContentEquals(ciphertext, storage.bytes)
    }

    @Test
    fun addEntry_onUnreadableVault_abortsWithoutWriting() = runBlocking {
        val corrupt = "not json".encodeToByteArray()
        val storage = FakeStorage(corrupt)
        repo(storage, FakeCrypto()).addPasswordEntry(
            AddPassword.EntryData(entryName = "gmail", userName = "a", password = "p", website = "w", notes = "n"),
        )

        assertEquals(0, storage.writeCount, "a mutation must not overwrite an unreadable vault")
        assertContentEquals(corrupt, storage.bytes)
    }

    @Test
    fun getEntries_onValidVault_returnsEntries() = runBlocking {
        // A single valid entry, serialized the same way the repository writes it.
        val json = """[{"id":"1","entryName":"gmail","username":"a","password":"p","website":"w","notes":"n","dateCreated":1}]"""
        val storage = FakeStorage(json.encodeToByteArray())
        val result = repo(storage, FakeCrypto()).getPasswordEntries()

        assertEquals(1, result.size)
        assertTrue(result.first().entryName == "gmail")
    }

    @Test
    fun pull_onUnparseablePeerVault_returnsErrorAndDoesNotWriteVault() = runBlocking {
        val existing = "[]".encodeToByteArray()
        val storage = FakeStorage(existing)
        val outcome = repo(
            storage = storage,
            crypto = FakeCrypto(),
            transferService = FakeTransfer("not json".encodeToByteArray()),
        ).pullPasswordDatabase(peerDevice("peer"))

        assertTrue(outcome is Outcome.Error)
        assertEquals(0, storage.writeCount)
        assertContentEquals(existing, storage.bytes)
    }
}
