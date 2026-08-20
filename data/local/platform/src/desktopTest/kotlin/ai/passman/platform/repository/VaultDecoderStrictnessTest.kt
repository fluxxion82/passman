package ai.passman.platform.repository

import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.platform.transfer.PasswordTransferService
import ai.passman.repo.Platform
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * What the vault decoder does with a field it has never heard of: **ignores it, deliberately.**
 *
 * The trade was weighed rather than drive-by'd. Strict decoding *sounds* like the safer setting on a
 * vault, but the strictness never guards what it appears to guard: the plaintext only ever comes out
 * of a successful AES-GCM decrypt, so corruption and tampering are rejected by the tag before any
 * JSON is seen, and an unknown key can only mean one thing — a *newer build of this app* wrote the
 * row. Task 5b's `uuid` demonstrated the cost of rejecting that: a strict peer cannot parse a sync
 * pull from an upgraded device, so every field addition forcibly breaks cross-version sync. This
 * release breaks it anyway (both devices must upgrade for uuids); tolerating unknown keys is what
 * makes the *next* field addition not break it again.
 *
 * What lenience does not cover — and must not — is structural damage: plaintext that is not a JSON
 * entry list at all still fails the parse, still reports unreadable, and still leaves the ciphertext
 * untouched. The last test pins that the loosening stopped at unknown *keys*.
 *
 * Fixtures here are hand-written JSON strings, not `Json.encodeToString` round trips: the whole
 * point is a payload this build's encoder would never produce.
 */
class VaultDecoderStrictnessTest {

    private lateinit var root: File
    private lateinit var storage: JvmPasswordDatabaseStorage
    private lateinit var vaultCipher: VaultCipher
    private lateinit var prefs: FakePreferences
    private lateinit var sessionKey: VaultSessionKey

    private val user = "erin"

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("vault-decoder").toFile()
        storage = JvmPasswordDatabaseStorage(object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        })
        vaultCipher = PasswordVaultCipher()
        prefs = FakePreferences()

        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                    }
                },
            )
        }
        sessionKey = vaultCipher.createSession("emerald orchard midnight").sessionKey
        runBlocking {
            KoinPlatform.getKoin()
                .getOrCreateScope("session-${prefs.getSessionId()}", named("sessionScope"))
                .get<VaultSession>(named(VAULT_SESSION_HANDLE))
                .bind(sessionKey)
        }
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        root.deleteRecursively()
    }

    @Test
    fun `a vault row carrying a field from a newer build still opens`() = runBlocking<Unit> {
        sealVault(
            """[{"id":"1","entryName":"lighthouse","username":"erin","password":"pw","website":"","notes":"",""" +
                """"dateCreated":900,"uuid":"u-1","totpSeed":"JBSWY3DPEHPK3PXP"}]""",
        )

        val read = repository().getPasswordEntries()

        assertEquals(listOf("lighthouse"), read.map { it.entryName }, "an unknown key is a newer field, not damage")
    }

    @Test
    fun `a sync pull carrying a field from a newer build merges instead of failing`() = runBlocking<Unit> {
        sealVault(
            """[{"id":"1","entryName":"lighthouse","username":"erin","password":"pw","website":"","notes":"",""" +
                """"dateCreated":900,"uuid":"u-1"}]""",
        )
        val peer =
            """[{"id":"1","entryName":"windmill","username":"erin","password":"pw2","website":"","notes":"",""" +
                """"dateCreated":901,"uuid":"u-2","passkeyBlob":"AAAA"}]"""

        val outcome = repository(transfer = FakeTransfer(peer.encodeToByteArray())).pullPasswordDatabase(peerDevice("peer-host"))

        assertIs<Outcome.Success<Unit>>(outcome, "an upgraded peer's extra field must not fail the pull")
        assertEquals(
            listOf("lighthouse", "windmill"),
            repository().getPasswordEntries().map { it.entryName },
        )
    }

    /** The boundary of the lenience: not-a-vault is still not a vault. */
    @Test
    fun `plaintext that is not an entry list is still rejected and the ciphertext preserved`() = runBlocking<Unit> {
        val sealed = sealVault("""{"this-is":"not an entry list"}""")

        val read = repository().getPasswordEntries()

        assertEquals(emptyList(), read, "unparseable plaintext reads as unreadable, never as empty-and-writable")
        assertContentEquals(sealed, storage.read(user), "and must never be written over")
    }

    // ------------------------------------------------------------- fixtures

    private fun repository(transfer: PasswordTransferService = FakeTransfer()) = LocalPasswordRepository(
        userPreferences = prefs,
        coroutinesContextFacade = UnconfinedFacade,
        vaultCipher = vaultCipher,
        storage = storage,
        transferService = transfer,
        entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
    )

    private fun sealVault(json: String): ByteArray {
        val sealed = vaultCipher.encryptVault(json.encodeToByteArray(), sessionKey)
        storage.create(user, sealed)
        return sealed
    }

    private class FakeTransfer(private val pullBytes: ByteArray = ByteArray(0)) : PasswordTransferService {
        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            hostName: String,
            port: Int,
        ) = Outcome.Success(Unit)

        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            device: TrustedDevice,
            port: Int,
        ) = Outcome.Success(Unit)

        override suspend fun pullDatabase(device: TrustedDevice, port: Int) = Outcome.Success(pullBytes)
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("erin", Password("h", "s"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "vault-decoder-test"
        override suspend fun clear() = Unit
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }
}
