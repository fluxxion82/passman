package ai.passman.repo.crypto

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.MlDsa
import ai.passman.crypto.keyring.KeyringEnvelope
import ai.passman.crypto.keyring.KeyringSubkeys
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultFailure
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.logging.KLogger
import ai.passman.logging.Logger
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.KdfParams
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyPairGenerator
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * The ML-DSA signing seed, under the same rules as `hybrid.key` — see [HybridKeyManagerTest] for why
 * each property is here rather than only there.
 *
 * One thing is worse on this side. After a pairing upgrade a peer rejects any envelope signed by an
 * ML-DSA key other than the one it recorded, so a silently regenerated seed does not degrade sync to
 * a slower path, it stops it outright and the failure names neither this file nor the event that
 * replaced it.
 *
 * No `assertFails` anywhere: it wraps `runCatching`, which catches `Throwable`.
 */
class MlDsaKeyManagerTest {
    private lateinit var localDir: File
    private lateinit var dmk: ByteArray
    private lateinit var keyringBytes: ByteArray
    private lateinit var sessionKey: VaultSessionKey

    private val vaultCipher = PasswordVaultCipher()
    private val crypto = RecordingCryptoService()
    private val logs = CapturingLogger()

    private var legacyKey: CryptoKey? = CryptoKey(RSA.private)

    private class FakePlatform(private val localPath: File) : Platform() {
        override fun getLocalPath(): String = localPath.absolutePath
    }

    /** As in [HybridKeyManagerTest]: real v2 envelopes, a call counter, and the post-decrypt hook. */
    private class RecordingCryptoService : CryptoService {
        private val delegate = JvmCryptoService()
        val decryptCount = AtomicInteger()
        var afterDecrypt: (() -> Unit)? = null

        override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray =
            delegate.encryptBytes(plain, publicKey)

        override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray {
            decryptCount.incrementAndGet()
            return delegate.decryptBytes(cipher, privateKey).also { afterDecrypt?.invoke() }
        }
    }

    /** See [HybridKeyManagerTest] for why the surfaced message is asserted behaviour. */
    private class CapturingLogger : Logger {
        private val entries = mutableListOf<Pair<Logger.Priority, String?>>()

        override fun log(
            priority: Logger.Priority,
            explicitTag: String?,
            inferredTag: String,
            message: String?,
            throwable: Throwable?,
            properties: Map<String, String>?,
        ) {
            entries += priority to message
        }

        fun errors(): List<String> =
            entries.filter { it.first == Logger.Priority.ERROR }.mapNotNull { it.second }
    }

    private class FakePrefs : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("password", "salt"))
        override suspend fun upsert(user: AppUser) {}
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) {}
        override suspend fun getSessionId(): String = "mldsa-key-test"
        override suspend fun clear() {}
    }

    private class TrackingTrustedDevices(
        private var devices: List<TrustedDevice>,
    ) : TrustedDevicesRepository {
        override fun observeAll(): Flow<List<TrustedDevice>> = flowOf(devices)
        override suspend fun getAll(): List<TrustedDevice> = devices
        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner): Boolean {
            devices = devices.filterNot { it.name == device.name } + device
            return true
        }
        override suspend fun remove(name: String) {
            devices = devices.filterNot { it.name == name }
        }
        override suspend fun getByHost(host: String): TrustedDevice? = devices.firstOrNull { it.lastHost == host }
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) {}
        override suspend fun updateHost(name: String, host: String) {}
        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) {}
        override suspend fun markSignedHybridPairingsForReverification() {
            devices = devices.map { device ->
                if (device.pairingSecurity == PairingSecurity.SignedHybridRequired) {
                    device.copy(pairingSecurity = PairingSecurity.AwaitingConfirmation)
                } else {
                    device
                }
            }
        }

        fun snapshot(): List<TrustedDevice> = devices
    }

    @BeforeTest
    fun setUp() {
        localDir = Files.createTempDirectory("mldsa-key-manager-test").toFile()
        KLogger.registerLoggers(logs)
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) {
                            legacyKey ?: error("the identity store was never opened on this session")
                        }
                    }
                },
            )
        }
        val created = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        keyringBytes = created.bytes
        dmk = created.dmk.copyOf()
        accountFile(DirectoryBundler.KEYRING_FILE_NAME).apply { parentFile.mkdirs() }.writeBytes(keyringBytes)
        runBlocking { logIn(keyringBytes, PASSWORD) }
        databaseDir().mkdirs()
        File(databaseDir(), "${"alice".hashCode()}_encrypted_passman.database").writeBytes(ByteArray(64) { 9 })
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        KLogger.unregisterLoggers(logs)
        localDir.deleteRecursively()
    }

    // --- generation ---------------------------------------------------------------------------

    @Test
    fun getKeyPair_persistsTheSeedUnderTheMlDsaKeyringSubkey() = runBlocking {
        val generated = assertNotNull(manager().getKeyPair())

        val stored = keyFile().readBytes()
        assertContentEquals("PMKF".encodeToByteArray(), stored.copyOfRange(0, 4))
        // By hand with the subkey rather than through KeyFileEnvelope: this is what fails if the seed
        // is ever wrapped under something vault-derived, which is the regression this task removes.
        assertContentEquals(generated.privateSeed, decryptWithSubkey(KeyringSubkeys.mlDsaKeyFileKey(dmk), stored))
        assertEquals(MlDsa.PRIVATE_SEED_BYTES, generated.privateSeed.size, "the stored blob is still the bare seed")
        assertEquals(0, crypto.decryptCount.get(), "a fresh key file must never touch the RSA identity")

        assertFailsWith<AEADBadTagException>("the hybrid label must not open the ML-DSA file") {
            decryptWithSubkey(KeyringSubkeys.hybridKeyFileKey(dmk), stored)
        }

        val reloaded = assertNotNull(manager().getKeyPair())
        assertContentEquals(generated.publicKey, reloaded.publicKey)
        assertContentEquals(generated.privateSeed, reloaded.privateSeed)
        // "There is no file" is the only state allowed to generate silently and preserve nothing.
        assertEquals(emptyList<File>(), quarantined())
        assertEquals(emptyList<String>(), logs.errors(), "first use is not an error condition")
    }

    /**
     * An existing file of zero bytes — see
     * [HybridKeyManagerTest.getKeyPair_zeroLengthKeyFileIsQuarantinedBeforeAReplacementIsGenerated].
     * Worse here: a regenerated seed is not a slower sync path, it is a peer that refuses this device
     * outright once the pairing is upgraded.
     */
    @Test
    fun getKeyPair_zeroLengthKeyFileIsQuarantinedBeforeAReplacementIsGenerated() = runBlocking {
        val file = keyFile().apply { parentFile.mkdirs(); writeBytes(ByteArray(0)) }
        assertTrue(file.isFile && file.length() == 0L, "precondition: the key file exists and is empty")

        val generated = assertNotNull(manager().getKeyPair())

        val quarantine = assertNotNull(
            quarantined().singleOrNull(),
            "an existing key file must never be replaced without a copy of it surviving",
        )
        assertEquals(0L, quarantine.length())
        assertEquals(
            listOf(DirectoryBundler.KEYRING_FILE_NAME, "mldsa.key"),
            file.parentFile.listFiles().orEmpty().map { it.name }.sorted(),
            "the quarantined copy must land outside keystore/<user>/ so keystore sync never bundles it",
        )
        assertEquals(0, crypto.decryptCount.get(), "an empty file is not a legacy RSA file")
        assertContentEquals("PMKF".encodeToByteArray(), file.readBytes().copyOfRange(0, 4))
        assertContentEquals(
            generated.publicKey,
            assertNotNull(manager().getKeyPair()).publicKey,
            "the replacement must be reloadable, not merely written",
        )
        assertTrue(surfaced(quarantine).isNotEmpty())
    }

    /** See [HybridKeyManagerTest.getKeyPair_zeroLengthKeyFileIsQuarantinedWithNoLegacyIdentityKey]. */
    @Test
    fun getKeyPair_zeroLengthKeyFileIsQuarantinedWithNoLegacyIdentityKey() = runBlocking {
        keyFile().apply { parentFile.mkdirs(); writeBytes(ByteArray(0)) }
        legacyKey = null

        assertNotNull(manager().getKeyPair(), "an empty file holds no RSA envelope for the legacy branch to protect")

        assertEquals(1, quarantined().size)
        assertContentEquals("PMKF".encodeToByteArray(), keyFile().readBytes().copyOfRange(0, 4))
    }

    // --- migration ----------------------------------------------------------------------------

    @Test
    fun getKeyPair_migratesAnRsaWrappedFileOntoTheKeyringSubkey() = runBlocking {
        val legacy = writeLegacyKeyFile()

        val loaded = assertNotNull(manager().getKeyPair())
        assertContentEquals(legacy.publicKey, loaded.publicKey, "migration must preserve the signing identity")
        assertEquals(1, crypto.decryptCount.get())

        val migrated = keyFile().readBytes()
        assertContentEquals("PMKF".encodeToByteArray(), migrated.copyOfRange(0, 4))
        assertContentEquals(legacy.privateSeed, decryptWithSubkey(KeyringSubkeys.mlDsaKeyFileKey(dmk), migrated))

        legacyKey = null
        assertContentEquals(legacy.publicKey, assertNotNull(manager().getKeyPair()).publicKey)
        assertEquals(1, crypto.decryptCount.get(), "no further RSA operation after the migration")
    }

    @Test
    fun getKeyPair_refusesToReplaceAnRsaWrappedFileWhenTheLegacyKeyIsUnavailable() = runBlocking {
        val legacy = writeLegacyKeyFile()
        val before = keyFile().readBytes()
        legacyKey = null

        assertNull(manager().getKeyPair(), "no legacy key means no answer, not a new signing identity")

        assertContentEquals(before, keyFile().readBytes())
        assertEquals(emptyList<File>(), quarantined())

        legacyKey = CryptoKey(RSA.private)
        assertContentEquals(legacy.publicKey, assertNotNull(manager().getKeyPair()).publicKey)
    }

    /** See [HybridKeyManagerTest.getKeyPair_migrationWriteFailureReturnsTheExistingKeyWithoutReplacingIt]. */
    @Test
    fun getKeyPair_migrationWriteFailureReturnsTheExistingKeyWithoutReplacingIt() = runBlocking {
        val legacy = writeLegacyKeyFile()
        val before = keyFile().readBytes()
        crypto.afterDecrypt = { sessionKey.destroy() }

        val loaded = assertNotNull(manager().getKeyPair(), "a key that decrypted is a key, whatever the rewrite did")

        assertContentEquals(legacy.publicKey, loaded.publicKey)
        assertContentEquals(before, keyFile().readBytes(), "a failed rewrite must not damage the original")
        assertEquals(emptyList<File>(), quarantined(), "nothing failed to decrypt, so nothing may be quarantined")

        crypto.afterDecrypt = null
        logIn(accountFile(DirectoryBundler.KEYRING_FILE_NAME).readBytes(), PASSWORD)
        assertContentEquals(legacy.publicKey, assertNotNull(manager().getKeyPair()).publicKey)
        assertContentEquals("PMKF".encodeToByteArray(), keyFile().readBytes().copyOfRange(0, 4))
    }

    @Test
    fun getKeyPair_refusesToReplaceAKeyFileWhenNoSessionIsBound() = runBlocking {
        assertNotNull(manager().getKeyPair())
        val before = keyFile().readBytes()
        vaultSession().destroy()

        assertNull(manager().getKeyPair())

        assertContentEquals(before, keyFile().readBytes())
        assertEquals(emptyList<File>(), quarantined())
    }

    // --- the regression that motivated the redesign --------------------------------------------

    /** See [HybridKeyManagerTest.getKeyPair_survivesVaultDatabaseDeletion] for why the shape matters. */
    @Test
    fun getKeyPair_survivesVaultDatabaseDeletion() = runBlocking {
        val before = assertNotNull(manager().getKeyPair())
        val fileBefore = keyFile().readBytes()

        assertTrue(databaseDir().deleteRecursively(), "precondition: the vault database directory existed")
        databaseDir().mkdirs()
        assertEquals(emptyList<File>(), databaseDir().listFiles().orEmpty().toList())

        logIn(accountFile(DirectoryBundler.KEYRING_FILE_NAME).readBytes(), PASSWORD)
        val after = assertNotNull(manager().getKeyPair())

        assertContentEquals(before.publicKey, after.publicKey, "losing the vault must not rotate the signing key")
        assertContentEquals(before.privateSeed, after.privateSeed)
        assertContentEquals(fileBefore, keyFile().readBytes())
        assertEquals(0, crypto.decryptCount.get())
    }

    @Test
    fun getKeyPair_survivesAPasswordChangeUnchanged() = runBlocking {
        val before = assertNotNull(manager().getKeyPair())
        val fileBefore = keyFile().readBytes()

        val rewrapped = vaultCipher.rewrapSession(sessionKey, NEW_PASSWORD)
        accountFile(DirectoryBundler.KEYRING_FILE_NAME).writeBytes(rewrapped)
        assertFailsWith<VaultFailure.WrongPassword>("precondition: the old password must stop working") {
            vaultCipher.unlockSession(rewrapped, PASSWORD)
        }

        logIn(rewrapped, NEW_PASSWORD)
        val after = assertNotNull(manager().getKeyPair())

        assertContentEquals(fileBefore, keyFile().readBytes(), "a password change must not touch mldsa.key")
        assertContentEquals(before.publicKey, after.publicKey)
    }

    // --- quarantine ---------------------------------------------------------------------------

    @Test
    fun getKeyPair_corruptFileQuarantinesAndGeneratesReloadableKeyPair() = runBlocking {
        val file = keyFile().apply { parentFile.mkdirs(); writeBytes("garbage".encodeToByteArray()) }

        val generated = assertNotNull(manager().getKeyPair())

        val quarantine = assertNotNull(quarantined().singleOrNull())
        assertTrue(file.parentFile.listFiles().orEmpty().none { it.name.startsWith("mldsa.key.corrupt-") })
        assertContentEquals("garbage".encodeToByteArray(), quarantine.readBytes())
        assertTrue(file.exists())
        assertContentEquals(generated.publicKey, assertNotNull(manager().getKeyPair()).publicKey)
        assertTrue(surfaced(quarantine).isNotEmpty())
    }

    /** See [HybridKeyManagerTest.getKeyPair_quarantineFailureLeavesTheFileAndGeneratesNothing]. */
    @Test
    fun getKeyPair_quarantineFailureLeavesTheFileAndGeneratesNothing() = runBlocking {
        val file = keyFile().apply { parentFile.mkdirs(); writeBytes("garbage".encodeToByteArray()) }
        val keystore = File(localDir, "keystore")
        Files.setPosixFilePermissions(
            keystore.toPath(),
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE),
        )
        try {
            assertNull(manager().getKeyPair(), "a file that could not be preserved must not be replaced")

            assertContentEquals("garbage".encodeToByteArray(), file.readBytes())
            assertEquals(emptyList<File>(), quarantined())
            assertEquals(
                listOf(DirectoryBundler.KEYRING_FILE_NAME, "mldsa.key"),
                file.parentFile.listFiles().orEmpty().map { it.name }.sorted(),
                "no replacement key and no publishing temp left behind",
            )
        } finally {
            Files.setPosixFilePermissions(
                keystore.toPath(),
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE,
                ),
            )
        }
    }

    /**
     * The corruption shape `"garbage"` can never reach: a well-formed keyring-era file with a damaged
     * tag, which exercises the post-migration read path rather than the legacy one.
     */
    @Test
    fun getKeyPair_damagedKeyFileEnvelopeQuarantinesAndRegenerates() = runBlocking {
        val original = assertNotNull(manager().getKeyPair())
        val file = keyFile()
        val damaged = file.readBytes().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        file.writeBytes(damaged)

        val regenerated = assertNotNull(manager().getKeyPair())

        assertFalse(original.publicKey.contentEquals(regenerated.publicKey))
        val quarantine = assertNotNull(quarantined().singleOrNull())
        assertContentEquals(damaged, quarantine.readBytes())
        assertEquals(0, crypto.decryptCount.get(), "a PMKF file must never be handed to the RSA reader")
        assertTrue(surfaced(quarantine).isNotEmpty())
    }

    @Test
    fun getKeyPair_regenerationMarksOnlySignedHybridPairingsForReverification() = runBlocking {
        val trustedDevices = pairedDevices()
        keyFile().apply { parentFile.mkdirs(); writeBytes("garbage".encodeToByteArray()) }

        assertNotNull(manager(trustedDevices).getKeyPair())

        assertEquals(
            listOf(
                PairingSecurity.LegacyRsa,
                PairingSecurity.AwaitingConfirmation,
                PairingSecurity.AwaitingConfirmation,
                PairingSecurity.AwaitingConfirmation,
            ),
            trustedDevices.snapshot().map { it.pairingSecurity },
        )
        assertTrue(surfaced(assertNotNull(quarantined().singleOrNull())).contains("keyring.pmk"))
    }

    @Test
    fun getKeyPair_successfulExistingKeyLoadDoesNotMarkSignedHybridPairingsStale() = runBlocking {
        val trustedDevices = pairedDevices()
        assertNotNull(manager(trustedDevices).getKeyPair(), "precondition: write a valid key file")

        assertNotNull(manager(trustedDevices).getKeyPair(), "a new manager must load the existing key file")

        assertEquals(
            listOf(
                PairingSecurity.LegacyRsa,
                PairingSecurity.SignedHybridRequired,
                PairingSecurity.AwaitingConfirmation,
                PairingSecurity.SignedHybridRequired,
            ),
            trustedDevices.snapshot().map { it.pairingSecurity },
        )
    }

    // --- concurrency --------------------------------------------------------------------------

    /** See [HybridKeyManagerTest.getKeyPair_concurrentFirstUseGeneratesExactlyOneKeyPair]. */
    @Test
    fun getKeyPair_concurrentFirstUseGeneratesExactlyOneKeyPair() = runBlocking {
        val manager = manager()
        val barrier = CyclicBarrier(2)

        val results = withContext(Dispatchers.IO) {
            (1..2).map {
                async {
                    barrier.await()
                    assertNotNull(manager.getKeyPair())
                }
            }.awaitAll()
        }

        assertEquals(1, results.map { it.publicKey.toList() }.toSet().size, "both callers must agree")
        assertEquals(
            listOf(DirectoryBundler.KEYRING_FILE_NAME, "mldsa.key"),
            keyFile().parentFile.listFiles().orEmpty().map { it.name }.sorted(),
            "no second key file and no publishing temp left behind",
        )
        assertContentEquals(
            results.first().privateSeed,
            decryptWithSubkey(KeyringSubkeys.mlDsaKeyFileKey(dmk), keyFile().readBytes()),
        )
    }

    // --- fixtures -----------------------------------------------------------------------------

    private fun manager(trustedDevices: TrustedDevicesRepository = TrackingTrustedDevices(emptyList())) =
        MlDsaKeyManager(FakePlatform(localDir), crypto, FakePrefs(), trustedDevices)

    private fun pairedDevices(): TrackingTrustedDevices = TrackingTrustedDevices(
        listOf(
            TrustedDevice("legacy", "10:00", "192.0.2.10"),
            TrustedDevice("signed-first", "20:00", "192.0.2.20", pairingSecurity = PairingSecurity.SignedHybridRequired),
            TrustedDevice("already-awaiting", "30:00", "192.0.2.30", pairingSecurity = PairingSecurity.AwaitingConfirmation),
            TrustedDevice("signed-second", "40:00", "192.0.2.40", pairingSecurity = PairingSecurity.SignedHybridRequired),
        ),
    )

    private fun keyFile(): File = accountFile("mldsa.key")

    private fun accountFile(name: String): File = File(localDir, "keystore/alice/$name")

    private fun databaseDir(): File = File(localDir, "database")

    /** Quarantined artifacts live one level up, in `keystore/`, so a keystore sync never bundles them. */
    private fun quarantined(): List<File> =
        File(localDir, "keystore").listFiles().orEmpty().filter { it.name.startsWith("mldsa.key.corrupt-") }

    /** See [HybridKeyManagerTest.surfaced]. */
    private fun surfaced(quarantine: File): String {
        val message = assertNotNull(
            logs.errors().singleOrNull { quarantine.absolutePath in it },
            "the quarantine path must be surfaced at error level: ${logs.errors()}",
        )
        assertTrue(
            DirectoryBundler.KEYRING_FILE_NAME in message,
            "a mismatched keyring produces this same failure with the key intact; the message must say so",
        )
        return message
    }

    /** An `mldsa.key` exactly as the pre-keyring build wrote it: the bare seed in a v2 RSA envelope. */
    private fun writeLegacyKeyFile(): MlDsa.KeyPair {
        val keyPair = MlDsa.generateKeyPair()
        keyFile().apply { parentFile.mkdirs() }
            .writeBytes(JvmCryptoService().encryptBytes(keyPair.privateSeed.copyOf(), CryptoKey(RSA.public)))
        return keyPair
    }

    private suspend fun logIn(keyring: ByteArray, password: String) {
        sessionKey = vaultCipher.unlockSession(keyring, password)
        vaultSession().bind(sessionKey)
    }

    private suspend fun vaultSession(): VaultSession = KoinPlatform.getKoin()
        .getOrCreateScope("session-${FakePrefs().getSessionId()}", named("sessionScope"))
        .get(named(VAULT_SESSION_HANDLE))

    /** Hand-rolled AES-GCM so the assertion never depends on the code under test agreeing with itself. */
    private fun decryptWithSubkey(key: ByteArray, sealed: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, sealed.copyOfRange(6, 18)),
            )
            updateAAD(sealed.copyOfRange(0, 18))
        }.doFinal(sealed.copyOfRange(18, sealed.size))

    private companion object {
        const val PASSWORD = "correct horse battery staple"
        const val NEW_PASSWORD = "a completely different horse"

        /** OWASP minimum: this suite unwraps a keyring several times per test and only needs a real one. */
        val TEST_PARAMS = KdfParams(
            algorithm = KdfParams.ARGON2ID,
            keyLengthBytes = 32,
            iterations = 2,
            memoryKib = 19_456,
            parallelism = 1,
        )

        /** One 2048-bit keygen for the whole class; the legacy fixtures only need a real RSA pair. */
        val RSA: java.security.KeyPair =
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }
}
