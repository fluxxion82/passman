package ai.passman.platform.repository

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.repo.Platform
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.settings.model.TransferEvent
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * The receive side's at-rest format.
 *
 * A payload that arrives over the wire is decrypted by the transport (suite v2/v3/v4 — that is
 * `EnvelopeCodec`'s business and Task 9's) and then has to be written *somewhere*. Before this change
 * it was re-sealed to the RSA at-rest format, which quietly reintroduced the exact wrapping the vault
 * migration removes: every sync would drag a migrated account back onto an RSA-wrapped vault, and the
 * `.premigration.v2` artifact would be describing a format the vault had returned to.
 *
 * The transport is deliberately not exercised here. Standing up two mTLS Netty servers to prove which
 * envelope the *storage* layer receives would test the network stack and assert almost nothing about
 * the vault, so the reconcile path — the public entry point that actually writes the vault — is what
 * is driven, with the staged file placed exactly as the receive handler places it.
 */
class TransferVaultFormatTest {

    private lateinit var root: File
    private lateinit var platform: Platform
    private lateinit var storage: JvmPasswordDatabaseStorage
    private lateinit var recorder: RecordingCryptoService
    private lateinit var vaultCipher: VaultCipher
    private lateinit var prefs: FakePreferences
    private lateinit var sessionKey: VaultSessionKey

    private val user = "alice"

    private val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val rsaPublic = CryptoKey(rsa.public)
    private val rsaPrivate = CryptoKey(rsa.private)

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("transfer-vault-format").toFile()
        platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        storage = JvmPasswordDatabaseStorage(platform)
        recorder = RecordingCryptoService(JvmCryptoService())
        vaultCipher = PasswordVaultCipher(recorder)
        prefs = FakePreferences()

        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                        scoped(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { rsaPublic }
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { rsaPrivate }
                    }
                },
            )
        }
        sessionKey = vaultCipher.createSession("correct horse battery staple").sessionKey
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
    fun `a reconciled overwrite persists the peer payload as suite five`() = runBlocking<Unit> {
        storage.create(user, vaultCipher.encryptVault(json(entry("gmail")), sessionKey))
        stage(vaultCipher.encryptVault(json(entry("from-peer")), sessionKey))
        recorder.reset()

        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Overwrite))

        assertTrue(isSuiteFive(storage.read(user)), "the reconciled vault must be suite 5")
        assertEquals(listOf("from-peer"), entryNames(storage.read(user)))
        assertEquals(0, recorder.encryptCalls, "an incoming payload must never be re-sealed as RSA v2")
        assertEquals(0, recorder.decryptCalls, "and a suite-5 staged file must not touch the RSA identity")
    }

    @Test
    fun `a reconciled merge persists the union as suite five`() = runBlocking<Unit> {
        storage.create(user, vaultCipher.encryptVault(json(entry("gmail")), sessionKey))
        stage(vaultCipher.encryptVault(json(entry("from-peer")), sessionKey))
        recorder.reset()

        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Merge))

        assertTrue(isSuiteFive(storage.read(user)))
        assertEquals(listOf("from-peer", "gmail"), entryNames(storage.read(user)))
        assertEquals(0, recorder.encryptCalls)
    }

    /**
     * The reconcile merge keys on `uuid`, and neither side is guaranteed to have one.
     *
     * A vault written before the field existed carries no `uuid` key at all, and it survives in that
     * state indefinitely: a legacy vault already in name order takes `getPasswordEntries`'
     * `renumbered == entries` branch, so `migrateVault` re-seals the plaintext verbatim and the rows
     * on disk are still uuid-less afterwards. The staged file can be uuid-less for the simpler reason
     * that the peer has not upgraded.
     *
     * Without the derivation in front of it, `associateBy { it.uuid }` over such a list keys every
     * row under `""` and keeps the last — the whole local vault collapses to one entry, and that one
     * entry is what gets published. So this asserts the row count and the identities, not just the
     * format, and it is deliberately the only case in this file with more than one row a side.
     */
    @Test
    fun `a reconciled merge keeps every row on both sides and gives each one an identity`() = runBlocking<Unit> {
        val local = json(
            entry("gmail", username = "alice"),
            entry("gmail", username = "bob"),
            entry("zoom", username = "z"),
        )
        assertTrue(
            !local.decodeToString().contains("uuid"),
            "fixture precondition: a pre-uuid vault has no uuid key for the merge to key on",
        )
        storage.create(user, vaultCipher.encryptVault(local, sessionKey))
        stage(
            vaultCipher.encryptVault(
                json(
                    entry("bank", username = "b"),
                    entry("zoom", username = "z", dateCreated = 2_000L, password = "rotated"),
                ),
                sessionKey,
            ),
        )

        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Merge))

        val merged = storedEntries()
        assertEquals(listOf("bank", "gmail", "gmail", "zoom"), merged.map { it.entryName })
        assertEquals(listOf("b", "alice", "bob", "z"), merged.map { it.username }, "no row on either side is lost")
        assertEquals("rotated", merged.first { it.entryName == "zoom" }.password, "the newer copy still wins")
        assertTrue(merged.none { it.uuid.isEmpty() }, "a published row with no identity cannot be addressed")
        assertEquals(merged.size, merged.map { it.uuid }.toSet().size, "and no two rows may share one")
    }

    /**
     * The same derivation on the Overwrite branch, where the failure is quieter: nothing is lost in
     * the moment, but every row lands in the vault without an identity, so the next mutation cannot
     * address one and the next merge collapses them all.
     */
    @Test
    fun `a reconciled overwrite gives the peer rows their identities`() = runBlocking<Unit> {
        storage.create(user, vaultCipher.encryptVault(json(entry("gmail")), sessionKey))
        stage(
            vaultCipher.encryptVault(
                json(entry("bank", username = "b"), entry("zoom", username = "z")),
                sessionKey,
            ),
        )

        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Overwrite))

        val stored = storedEntries()
        assertEquals(listOf("bank", "zoom"), stored.map { it.entryName })
        assertTrue(stored.none { it.uuid.isEmpty() }, "the peer's rows must arrive addressable")
        assertEquals(stored.size, stored.map { it.uuid }.toSet().size)
    }

    /**
     * A staged file left behind by a build that still wrote the RSA at-rest format. It has to keep
     * being readable — the user may update with one already sitting in `database/tmp` — but what
     * lands in the vault is suite 5 regardless of what arrived.
     */
    @Test
    fun `a legacy staged file is read but re-persisted as suite five`() = runBlocking<Unit> {
        val legacyVault = JvmCryptoService().encryptBytes(json(entry("gmail")), rsaPublic)
        storage.create(user, legacyVault)
        stage(JvmCryptoService().encryptBytes(json(entry("from-peer")), rsaPublic))

        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Merge))

        assertTrue(isSuiteFive(storage.read(user)), "the vault never goes back to RSA wrapping")
        assertEquals(listOf("from-peer", "gmail"), entryNames(storage.read(user)))
        assertContentEquals(
            legacyVault,
            File(root, "database/${user.hashCode()}_encrypted_passman.database.premigration.v2").readBytes(),
            "a reconcile that converts a legacy vault owes the user the same downgrade copy a login does",
        )
    }

    /**
     * The compatibility policy has one absolute in it: no suite-5 vault replaces a legacy one without
     * `.premigration.v2` beside it. Reconcile is the only write path that can convert a vault without
     * going through `LocalPasswordRepository`, so the rule has to hold here too.
     *
     * On **Merge** it is enforced. The local vault decrypted a few lines earlier, so there is
     * something to lose and aborting costs the user nothing but a retry — exactly the trade the login
     * path makes.
     */
    @Test
    fun `a merge that cannot retain the downgrade copy leaves the legacy vault untouched`() = runBlocking<Unit> {
        val legacyVault = JvmCryptoService().encryptBytes(json(entry("gmail")), rsaPublic)
        storage.create(user, legacyVault)
        stage(vaultCipher.encryptVault(json(entry("from-peer")), sessionKey))

        val outcome = repository(storage = FailingRetentionStorage(storage))
            .executeReconcileAction(ReconcileAction.Merge)

        assertIs<Outcome.Error>(outcome)
        assertContentEquals(
            legacyVault,
            storage.read(user),
            "an unretained legacy vault must not be converted by a reconcile either",
        )
        // The staged payload is still there, so the user can simply try again.
        assertTrue(File(root, "database/tmp/${user.hashCode()}").isFile)
        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Merge))
        assertTrue(isSuiteFive(storage.read(user)))
    }

    /**
     * **Overwrite** stays best-effort, and deliberately.
     *
     * Discarding the local vault is the entire point of the action — the user picked it, often
     * precisely because the local copy is the broken one, and it may not decrypt at all. Failing the
     * reconcile because a copy of bytes nobody can read could not be written would leave them unable
     * to take the peer's vault, which is the outcome they asked for.
     */
    @Test
    fun `an overwrite proceeds when the downgrade copy cannot be retained`() = runBlocking<Unit> {
        storage.create(user, JvmCryptoService().encryptBytes(json(entry("gmail")), rsaPublic))
        stage(vaultCipher.encryptVault(json(entry("from-peer")), sessionKey))

        val outcome = repository(storage = FailingRetentionStorage(storage))
            .executeReconcileAction(ReconcileAction.Overwrite)

        assertIs<Outcome.Success<Unit>>(outcome)
        assertEquals(listOf("from-peer"), entryNames(storage.read(user)))
    }

    /**
     * The reconcile decoder follows the same strictness decision as the repository's
     * (`VaultDecoderStrictnessTest`): an unknown key is a newer build's field, not damage — damage
     * never reaches the JSON, because the staged file has to pass an AEAD tag first. A strict
     * reconcile here would strand exactly the user reconcile exists for: one device upgraded, the
     * other behind by one field.
     */
    @Test
    fun `a staged file carrying a field from a newer build still reconciles`() = runBlocking<Unit> {
        storage.create(user, vaultCipher.encryptVault(json(entry("gmail")), sessionKey))
        val futureRow =
            """[{"id":"1","entryName":"from-newer-peer","username":"u","password":"p","website":"w",""" +
                """"notes":"n","dateCreated":2000,"uuid":"u-future","recoveryCodes":["a","b"]}]"""
        stage(vaultCipher.encryptVault(futureRow.encodeToByteArray(), sessionKey))

        assertIs<Outcome.Success<Unit>>(repository().executeReconcileAction(ReconcileAction.Merge))

        assertEquals(listOf("from-newer-peer", "gmail"), entryNames(storage.read(user)))
    }

    @Test
    fun `a staged file that does not decrypt leaves the vault untouched`() = runBlocking<Unit> {
        val vault = vaultCipher.encryptVault(json(entry("gmail")), sessionKey)
        storage.create(user, vault)
        stage("shredded".encodeToByteArray())

        assertIs<Outcome.Error>(repository().executeReconcileAction(ReconcileAction.Merge))

        assertContentEquals(vault, storage.read(user), "an unreadable staged file must not cost the user their vault")
    }

    // ---------------------------------------------------------------- setup

    private fun repository(storage: PasswordDatabaseStorage = this.storage) = FileTransferRepository(
        platform = platform,
        coroutineScopeFacade = ImmediateScopeFacade(),
        coroutinesContextFacade = UnconfinedFacade,
        transferEventPersistence = NoopTransferEvents,
        passwordEventPersistence = NoopPasswordEvents,
        passwordDatabaseStorage = storage,
        pgpEventPersistence = NoopPgpEvents,
        keystoreEventPersistence = NoopKeystoreEvents,
        userPreferences = prefs,
        ipAddressProvider = NoIpAddress,
        syncTlsProvider = SyncTlsProvider(userPreferences = prefs, trustedDevices = NoTrustedDevices),
        hybridKeyManager = HybridKeyManager(platform, recorder, prefs, NoTrustedDevices),
        mlDsaKeyManager = MlDsaKeyManager(platform, recorder, prefs, NoTrustedDevices),
        vaultCipher = vaultCipher,
        entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
        qrPairingSession = unarmedQrPairingSession(),
    )

    /** Exactly where the receive handler puts an inbound password database. */
    private fun stage(bytes: ByteArray) {
        File(root, "database/tmp").mkdirs()
        File(root, "database/tmp/${user.hashCode()}").writeBytes(bytes)
    }

    private fun entry(
        name: String,
        username: String = "u",
        password: String = "p",
        dateCreated: Long = 1_000L,
    ) = PasswordEntry(
        id = "1",
        dateCreated = dateCreated,
        entryName = name,
        password = password,
        website = "w",
        username = username,
        notes = "n",
    )

    /**
     * `encodeDefaults` is off by default, so `uuid = ""` is simply absent from the JSON — which is
     * exactly what a vault written before the field looks like.
     */
    private fun json(vararg entries: PasswordEntry): ByteArray =
        Json.encodeToString(entries.toList()).encodeToByteArray()

    private fun storedEntries(): List<PasswordEntry> =
        Json.decodeFromString(
            vaultCipher.decryptVault(storage.read(user), sessionKey) { rsaPrivate }.plaintext.decodeToString(),
        )

    private fun entryNames(vault: ByteArray): List<String> =
        Json.decodeFromString<List<PasswordEntry>>(
            vaultCipher.decryptVault(vault, sessionKey) { rsaPrivate }.plaintext.decodeToString(),
        ).map { it.entryName }

    private fun isSuiteFive(bytes: ByteArray): Boolean =
        bytes.size > 5 && bytes.copyOfRange(0, 4).contentEquals("PMNV".encodeToByteArray()) && bytes[5] == 5.toByte()

    // ---------------------------------------------------------------- fakes

    /** Real storage that cannot write the one-generation downgrade copy. */
    private class FailingRetentionStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        override fun retainPreMigration(username: String, ciphertext: ByteArray): Boolean =
            throw java.io.IOException("simulated retention failure")
    }

    private class RecordingCryptoService(private val delegate: CryptoService) : CryptoService {
        var encryptCalls = 0
            private set
        var decryptCalls = 0
            private set

        override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray {
            encryptCalls++
            return delegate.encryptBytes(plain, publicKey)
        }

        override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray {
            decryptCalls++
            return delegate.decryptBytes(cipher, privateKey)
        }

        fun reset() {
            encryptCalls = 0
            decryptCalls = 0
        }
    }

    private class ImmediateScopeFacade : CoroutineScopeFacade {
        override val globalScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        override var transferScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
    }

    private object NoopTransferEvents : TransferEventPersistence {
        override fun events(): Flow<TransferEvent> = emptyFlow()
        override suspend fun update(event: TransferEvent) = Unit
    }

    private object NoopPasswordEvents : PasswordEventPersistence {
        override fun events(): Flow<PasswordEvent> = emptyFlow()
        override suspend fun update(event: PasswordEvent) = Unit
    }

    private object NoopPgpEvents : PgpEventPersistence {
        override fun events(): Flow<PgpEvent> = emptyFlow()
        override suspend fun update(event: PgpEvent) = Unit
    }

    private object NoopKeystoreEvents : KeystoreEventPersistence {
        override fun events(): Flow<KeystoreEvent> = emptyFlow()
        override suspend fun update(event: KeystoreEvent) = Unit
    }

    private object NoIpAddress : IpAddressProvider {
        override suspend fun getLocalIpAddress(): String = "127.0.0.1"
    }

    private object NoTrustedDevices : TrustedDevicesRepository {
        override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
        override suspend fun getAll(): List<TrustedDevice> = emptyList()
        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
        override suspend fun remove(name: String) = Unit
        override suspend fun getByHost(host: String): TrustedDevice? = null
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
        override suspend fun updateHost(name: String, host: String) = Unit
        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
        override suspend fun markSignedHybridPairingsForReverification() = Unit
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("h", "s"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "transfer-vault-format-test"
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
