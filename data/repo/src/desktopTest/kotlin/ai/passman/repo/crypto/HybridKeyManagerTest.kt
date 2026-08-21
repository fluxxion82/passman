package ai.passman.repo.crypto

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.HybridKem
import ai.passman.crypto.JvmCryptoService
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
 * `hybrid.key` is now sealed under `KeyringSubkeys.hybridKeyFileKey(dmk)` rather than under the RSA
 * identity, and — the point of the whole task — under nothing that comes from the vault.
 *
 * Two properties this suite exists to pin, both of which fail *silently* in production:
 *
 * - **Deleting the vault database must not invalidate the key.** If the file key were derived from a
 *   root stored inside the vault envelope, a restore or a loss would change it, every upgraded
 *   pairing would break, and the only recovery would be re-pairing every peer by hand. The regression
 *   would surface days later as "sync stopped working", with nothing pointing at the vault restore.
 * - **A valid key is never silently replaced.** Generating a fresh keypair when an intact file could
 *   not be read orphans every peer holding the old public key, with no error anywhere.
 *
 * No `assertFails` anywhere: it wraps `runCatching`, which catches `Throwable`, so an
 * `OutOfMemoryError` would read as a pass.
 */
class HybridKeyManagerTest {
    private lateinit var localDir: File
    private lateinit var dmk: ByteArray
    private lateinit var keyringBytes: ByteArray
    private lateinit var sessionKey: VaultSessionKey

    private val vaultCipher = PasswordVaultCipher()
    private val crypto = RecordingCryptoService()
    private val logs = CapturingLogger()

    /**
     * Nullable so a test can model the one state that must never end in a regenerated key: a
     * pre-keyring RSA-wrapped file on disk and no legacy identity key to open it with.
     */
    private var legacyKey: CryptoKey? = CryptoKey(RSA.private)

    private class FakePlatform(private val localPath: File) : Platform() {
        override fun getLocalPath(): String = localPath.absolutePath
    }

    /**
     * The real envelope, so the legacy fixtures are genuine "PMNV" v2 files, plus a call counter and
     * an [afterDecrypt] hook. The hook is how a test reaches the one-instruction window between "the
     * legacy file decrypted" and "the rewrite under the subkey" without mocking the manager's file IO.
     */
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

    /**
     * What the manager surfaced, by priority.
     *
     * Quarantining a key file replaces this device's pairing identity, and there is nowhere else for
     * that to go yet — marking the affected `TrustedDevice`s needs `PairingSecurity`, which arrives
     * with plan Task 7 (step 2b). Until then an error-level line naming the quarantine path is the
     * user's only route back to the old identity, so it is asserted behaviour rather than a nicety.
     */
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
        override suspend fun getSessionId(): String = "hybrid-key-test"
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
        localDir = Files.createTempDirectory("hybrid-key-manager-test").toFile()
        KLogger.registerLoggers(logs)
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                        // Mirrors production: the definition throws rather than returning null when the
                        // login never warmed the identity store, which is why the manager resolves it
                        // through runCatching.
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) {
                            legacyKey ?: error("the identity store was never opened on this session")
                        }
                    }
                },
            )
        }
        // A real keyring on disk, in the place production puts it, so a "log in" in a test can unwrap
        // it again rather than reusing a session key that is already in memory.
        val created = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        keyringBytes = created.bytes
        dmk = created.dmk.copyOf()
        accountFile(DirectoryBundler.KEYRING_FILE_NAME).apply { parentFile.mkdirs() }.writeBytes(keyringBytes)
        runBlocking { logIn(keyringBytes, PASSWORD) }
        // The vault database the headline test later deletes. Content is irrelevant — what matters is
        // that it exists first, so "deleted the database" is a real transition and not a no-op.
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
    fun getKeyPair_sealsTheKeyFileUnderTheHybridKeyringSubkey() = runBlocking {
        val generated = assertNotNull(manager().getKeyPair())

        val stored = keyFile().readBytes()
        assertContentEquals("PMKF".encodeToByteArray(), stored.copyOfRange(0, 4), "the keyring key-file envelope")
        // Decrypted by hand with the subkey, not through KeyFileEnvelope: this is the assertion that
        // fails if the implementation ever wraps the file under anything else — a vault-derived root,
        // the RSA identity, the other label — and it is the whole reason this task exists.
        val blob = decryptWithSubkey(KeyringSubkeys.hybridKeyFileKey(dmk), stored)
        assertContentEquals(generated.privateKey.x25519, blob.copyOfRange(0, 32))
        assertEquals(0, crypto.decryptCount.get(), "a fresh key file must never touch the RSA identity")

        assertFailsWith<AEADBadTagException>("the ML-DSA label must not open the hybrid file") {
            decryptWithSubkey(KeyringSubkeys.mlDsaKeyFileKey(dmk), stored)
        }
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(generated.publicKey),
            EnvelopeCodec.serializePublicKey(assertNotNull(manager().getKeyPair()).publicKey),
            "a second login must reload the same identity, not mint a new one",
        )
        // "There is no file" is the *only* state that may generate without preserving anything and
        // without telling anyone. Every other state that generates has to leave both behind.
        assertEquals(emptyList<File>(), quarantined())
        assertEquals(emptyList<String>(), logs.errors(), "first use is not an error condition")
    }

    /**
     * An existing file of zero bytes.
     *
     * This is what a crash between create and write, a full disk, or a half-finished restore leaves
     * behind, and it was the one shape the guard classified as *absent*: quarantine skipped, a new
     * identity generated and published in place, every already-paired peer orphaned, and nothing in
     * the log. Empty is not a format — it is neither a PMKF envelope nor an RSA-wrapped one — so it is
     * decided before the legacy branch, which is what `decryptCount` pins.
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
            listOf("hybrid.key", DirectoryBundler.KEYRING_FILE_NAME),
            file.parentFile.listFiles().orEmpty().map { it.name }.sorted(),
            "the quarantined copy must land outside keystore/<user>/ so keystore sync never bundles it",
        )
        assertEquals(0, crypto.decryptCount.get(), "an empty file is not a legacy RSA file")
        assertContentEquals("PMKF".encodeToByteArray(), file.readBytes().copyOfRange(0, 4))
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(generated.publicKey),
            EnvelopeCodec.serializePublicKey(assertNotNull(manager().getKeyPair()).publicKey),
            "the replacement must be reloadable, not merely written",
        )
        assertTrue(surfaced(quarantine).isNotEmpty())
    }

    /**
     * The same file with no legacy identity key available.
     *
     * Separate from the test above because it separates two different fixes. Widening the guard to
     * `file.exists()` alone sends an empty file down the legacy branch, where the refusal meant for a
     * possibly-intact RSA-wrapped key claims it and the account is left with no hybrid identity at
     * all, permanently. Empty has to be classified as unusable in its own right.
     */
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
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(legacy.publicKey),
            EnvelopeCodec.serializePublicKey(loaded.publicKey),
            "migration must preserve the identity every already-paired peer holds",
        )
        assertEquals(1, crypto.decryptCount.get())

        val migrated = keyFile().readBytes()
        assertContentEquals("PMKF".encodeToByteArray(), migrated.copyOfRange(0, 4), "rewritten under the subkey")
        assertContentEquals(
            legacy.privateKey.x25519,
            decryptWithSubkey(KeyringSubkeys.hybridKeyFileKey(dmk), migrated).copyOfRange(0, 32),
        )

        // Once migrated, the RSA identity is never consulted again — assert it by taking the legacy
        // key away entirely rather than by trusting the counter.
        legacyKey = null
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(legacy.publicKey),
            EnvelopeCodec.serializePublicKey(assertNotNull(manager().getKeyPair()).publicKey),
        )
        assertEquals(1, crypto.decryptCount.get(), "no further RSA operation after the migration")
    }

    /**
     * The state that must never end in a regenerated key: the file is RSA-wrapped and quite possibly
     * perfectly intact, but this device cannot open it right now. Generating here would orphan every
     * peer holding the old public key, and the user would have no way to know why sync stopped.
     */
    @Test
    fun getKeyPair_refusesToReplaceAnRsaWrappedFileWhenTheLegacyKeyIsUnavailable() = runBlocking {
        val legacy = writeLegacyKeyFile()
        val before = keyFile().readBytes()
        legacyKey = null

        assertNull(manager().getKeyPair(), "no legacy key means no answer, not a new identity")

        assertContentEquals(before, keyFile().readBytes(), "the file must be left exactly as it was")
        assertEquals(emptyList<File>(), quarantined(), "nothing was proven broken, so nothing may be quarantined")

        // ...and once the identity store opens, the original identity comes back untouched.
        legacyKey = CryptoKey(RSA.private)
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(legacy.publicKey),
            EnvelopeCodec.serializePublicKey(assertNotNull(manager().getKeyPair()).publicKey),
        )
    }

    /**
     * The legacy file opened fine and only the rewrite failed. The key in hand is *valid*, so it is
     * returned and the file is left alone: neither replaced with a fresh identity nor quarantined.
     *
     * The failure is injected through the session key rather than through file permissions, because
     * `persist` runs `SecureFiles.ownerOnlyDir` on `keystore/<user>/` first and that puts owner-write
     * straight back — a read-only directory does not survive to the write.
     */
    @Test
    fun getKeyPair_migrationWriteFailureReturnsTheExistingKeyWithoutReplacingIt() = runBlocking {
        val legacy = writeLegacyKeyFile()
        val before = keyFile().readBytes()
        // Destroying the session key between the decrypt and the rewrite: the read has already
        // succeeded, and every path in persist() needs the master key.
        crypto.afterDecrypt = { sessionKey.destroy() }

        val loaded = assertNotNull(manager().getKeyPair(), "a key that decrypted is a key, whatever the rewrite did")

        assertContentEquals(
            EnvelopeCodec.serializePublicKey(legacy.publicKey),
            EnvelopeCodec.serializePublicKey(loaded.publicKey),
        )
        assertContentEquals(before, keyFile().readBytes(), "a failed rewrite must not damage the original")
        assertEquals(emptyList<File>(), quarantined(), "nothing failed to decrypt, so nothing may be quarantined")

        // ...and the migration is merely deferred, exactly as the failure is logged: the next login
        // opens the same file again and completes it.
        crypto.afterDecrypt = null
        logIn(accountFile(DirectoryBundler.KEYRING_FILE_NAME).readBytes(), PASSWORD)
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(legacy.publicKey),
            EnvelopeCodec.serializePublicKey(assertNotNull(manager().getKeyPair()).publicKey),
        )
        assertContentEquals("PMKF".encodeToByteArray(), keyFile().readBytes().copyOfRange(0, 4))
    }

    /** The same rule for the post-migration format: no session key, no answer — and no new key. */
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

    /**
     * Delete the vault database, log in again, and the device must still hold the same hybrid
     * identity.
     *
     * The shape matters. The session key is destroyed and re-derived by unwrapping `keyring.pmk` off
     * disk, because reusing the `VaultSessionKey` already in memory would pass even if the file key
     * were vault-derived — the very bug this asserts against. The database directory is populated
     * first and emptied here, so "the database is gone" is a real transition.
     */
    @Test
    fun getKeyPair_survivesVaultDatabaseDeletion() = runBlocking {
        val before = assertNotNull(manager().getKeyPair())
        val fileBefore = keyFile().readBytes()

        assertTrue(databaseDir().deleteRecursively(), "precondition: the vault database directory existed")
        databaseDir().mkdirs() // restored empty, exactly as a wiped-database recovery leaves it
        assertEquals(emptyList<File>(), databaseDir().listFiles().orEmpty().toList())

        // A fresh login: the master key comes back out of keyring.pmk, nothing is reused.
        logIn(accountFile(DirectoryBundler.KEYRING_FILE_NAME).readBytes(), PASSWORD)
        val after = assertNotNull(manager().getKeyPair())

        assertContentEquals(
            EnvelopeCodec.serializePublicKey(before.publicKey),
            EnvelopeCodec.serializePublicKey(after.publicKey),
            "losing the vault must not cost the device its pairing identity",
        )
        assertContentEquals(fileBefore, keyFile().readBytes(), "and must not rewrite the key file either")
        assertEquals(0, crypto.decryptCount.get())
    }

    /**
     * A password change rewraps `keyring.pmk` and nothing else: the device master key does not
     * rotate, so this file stays byte-identical and still opens.
     *
     * Both halves are needed. Bytes alone would pass if the key had silently become unopenable;
     * opening alone would pass if the manager had quietly rewritten the file, which on a crash
     * between the two writes is exactly the window that loses an identity.
     */
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

        assertContentEquals(fileBefore, keyFile().readBytes(), "a password change must not touch hybrid.key")
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(before.publicKey),
            EnvelopeCodec.serializePublicKey(after.publicKey),
        )
    }

    // --- quarantine ---------------------------------------------------------------------------

    @Test
    fun getKeyPair_corruptFileQuarantinesAndGeneratesReloadableKeyPair() = runBlocking {
        val file = keyFile().apply { parentFile.mkdirs(); writeBytes("garbage".encodeToByteArray()) }

        val generated = assertNotNull(manager().getKeyPair())

        val quarantine = assertNotNull(quarantined().singleOrNull())
        assertTrue(file.parentFile.listFiles().orEmpty().none { it.name.startsWith("hybrid.key.corrupt-") })
        assertContentEquals("garbage".encodeToByteArray(), quarantine.readBytes())
        assertTrue(file.exists())
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(generated.publicKey),
            EnvelopeCodec.serializePublicKey(assertNotNull(manager().getKeyPair()).publicKey),
        )
        assertTrue(surfaced(quarantine).isNotEmpty())
    }

    /**
     * An unreadable file that cannot be moved out of the way. Failing to preserve it is not a licence
     * to write over it — the bytes may be a perfectly good identity behind a mismatched keyring, and
     * once they are gone the only recovery is re-pairing every peer by hand.
     *
     * `keystore/` is the lever because nothing on this path ever chmods it back, unlike
     * `keystore/<user>/`, which `SecureFiles.ownerOnlyDir` restores to 0700 on every persist.
     */
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
                listOf("hybrid.key", DirectoryBundler.KEYRING_FILE_NAME),
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
     * The other corruption shape, and the one the old fixture could never reach: a *well-formed*
     * keyring-era file whose ciphertext was damaged. `"garbage"` has no "PMKF" magic, so it goes down
     * the legacy branch and leaves the entire post-migration read path untested.
     */
    @Test
    fun getKeyPair_damagedKeyFileEnvelopeQuarantinesAndRegenerates() = runBlocking {
        val original = assertNotNull(manager().getKeyPair())
        val file = keyFile()
        val damaged = file.readBytes().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        file.writeBytes(damaged)

        val regenerated = assertNotNull(manager().getKeyPair())

        assertFalse(
            EnvelopeCodec.serializePublicKey(original.publicKey)
                .contentEquals(EnvelopeCodec.serializePublicKey(regenerated.publicKey)),
            "an unreadable file is replaced, which is why it has to be preserved outside keystore/<user>/",
        )
        val quarantine = assertNotNull(quarantined().singleOrNull())
        assertContentEquals(damaged, quarantine.readBytes())
        assertEquals(0, crypto.decryptCount.get(), "a PMKF file must never be handed to the RSA reader")
        // A failed tag says "damaged file" and "wrong device master key" in exactly the same way, so
        // the message has to point at the keyring as well as at the preserved bytes.
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

    /**
     * Two callers reaching first use at the same time must produce one keypair, not two.
     *
     * Without the load mutex both generate, both write, one file wins, and the caller that lost has
     * already handed its public key to a peer that will never be able to reach this device again.
     * The barrier is what makes that reachable: without it the second call almost always arrives
     * after the first has cached.
     */
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

        val serialized = results.map { EnvelopeCodec.serializePublicKey(it.publicKey).toList() }
        assertEquals(1, serialized.toSet().size, "both callers must receive the same identity")
        assertEquals(
            listOf("hybrid.key", DirectoryBundler.KEYRING_FILE_NAME),
            keyFile().parentFile.listFiles().orEmpty().map { it.name }.sorted(),
            "no second key file and no publishing temp left behind",
        )
        // The winner's key is the one on disk: a loser that overwrote it would leave the returned
        // public key orphaned even though both callers agreed.
        assertContentEquals(
            results.first().privateKey.x25519,
            decryptWithSubkey(KeyringSubkeys.hybridKeyFileKey(dmk), keyFile().readBytes()).copyOfRange(0, 32),
        )
    }

    /**
     * Two *managers* — the shape two processes have, which the per-instance load mutex cannot
     * serialise. Both can pass `file.exists()` and both generate; before the `O_EXCL` claim the
     * loser's rename silently replaced the winner's file, so a caller could walk away holding a
     * keypair that was no longer on disk — the orphaned-identity bug, from inside one JVM.
     *
     * The interleaving is not forced (there is deliberately no seam inside `loadOrCreate`), so this
     * asserts the invariant that must hold under *every* interleaving: at least one caller gets a
     * keypair, every keypair handed out matches the file on disk, and a loser gets `null` — never a
     * key of its own invention. Under the pre-claim code the racing outcome violated the disk-match
     * half; under the claim it cannot.
     */
    @Test
    fun getKeyPair_twoManagersRacingFirstUseNeverHandOutAKeyThatIsNotOnDisk() = runBlocking {
        val barrier = CyclicBarrier(2)
        val results = withContext(Dispatchers.IO) {
            listOf(manager(), manager()).map { racer ->
                async {
                    barrier.await()
                    racer.getKeyPair()
                }
            }.awaitAll()
        }

        val returned = results.filterNotNull()
        assertTrue(returned.isNotEmpty(), "somebody must win the claim")
        val onDiskX25519 = decryptWithSubkey(KeyringSubkeys.hybridKeyFileKey(dmk), keyFile().readBytes())
            .copyOfRange(0, 32)
        returned.forEach { keyPair ->
            assertContentEquals(
                onDiskX25519,
                keyPair.privateKey.x25519,
                "a caller may lose the claim and get null, but must never hold a key the disk does not",
            )
        }
        // Split in two on purpose. `listFiles()` returns null when the path is not a directory, and
        // `.orEmpty()` used to collapse that into the same "[]" as a genuinely empty directory — which
        // is exactly the shape this test failed with once, on 2026-08-21, in a full `projectTest` run
        // and never since (not in ~10 subsequent full and isolated runs). The message could not say
        // which of the two had happened, so the cause is still unknown.
        //
        // Reading `hybrid.key` two lines above had just succeeded, so the directory existed then. If
        // this fires again, the first assertion says whether it stopped being a directory rather than
        // leaving the next person to re-derive that from a bare "[]".
        val accountDir = keyFile().parentFile
        val listing = accountDir.listFiles()
        assertNotNull(
            listing,
            "listFiles() returned null for $accountDir (exists=${accountDir.exists()}, " +
                "isDirectory=${accountDir.isDirectory}) - the account directory stopped being a " +
                "directory between reading hybrid.key and listing it",
        )
        assertEquals(
            listOf("hybrid.key", DirectoryBundler.KEYRING_FILE_NAME),
            listing.map { it.name }.sorted(),
            "no second key file and no publishing temp left behind",
        )
    }

    // --- fixtures -----------------------------------------------------------------------------

    private fun manager(trustedDevices: TrustedDevicesRepository = TrackingTrustedDevices(emptyList())) =
        HybridKeyManager(FakePlatform(localDir), crypto, FakePrefs(), trustedDevices)

    private fun pairedDevices(): TrackingTrustedDevices = TrackingTrustedDevices(
        listOf(
            TrustedDevice("legacy", "10:00", "192.0.2.10"),
            TrustedDevice("signed-first", "20:00", "192.0.2.20", pairingSecurity = PairingSecurity.SignedHybridRequired),
            TrustedDevice("already-awaiting", "30:00", "192.0.2.30", pairingSecurity = PairingSecurity.AwaitingConfirmation),
            TrustedDevice("signed-second", "40:00", "192.0.2.40", pairingSecurity = PairingSecurity.SignedHybridRequired),
        ),
    )

    private fun keyFile(): File = accountFile("hybrid.key")

    private fun accountFile(name: String): File = File(localDir, "keystore/alice/$name")

    private fun databaseDir(): File = File(localDir, "database")

    /** Quarantined artifacts live one level up, in `keystore/`, so a keystore sync never bundles them. */
    private fun quarantined(): List<File> =
        File(localDir, "keystore").listFiles().orEmpty().filter { it.name.startsWith("hybrid.key.corrupt-") }

    /**
     * The error-level line that tells the user what just happened to their pairings, or a failure.
     *
     * A quarantine means this device's identity changed, and until `PairingSecurity` lands (plan Task
     * 7, step 2b) nothing marks the affected `TrustedDevice`s. So the message has to carry the two
     * facts the user cannot recover otherwise: where the old bytes went, and that a restored or
     * mismatched keyring produces this same failure with the key perfectly intact.
     */
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

    /** A `hybrid.key` exactly as the pre-keyring build wrote it: the private blob in a v2 RSA envelope. */
    private fun writeLegacyKeyFile(): HybridKem.KeyPair {
        val keyPair = HybridKem.generateKeyPair()
        val priv = keyPair.privateKey
        val blob = ByteArray(34 + priv.mlkem.size)
        priv.x25519.copyInto(blob, 0)
        blob[32] = ((priv.mlkem.size ushr 8) and 0xFF).toByte()
        blob[33] = (priv.mlkem.size and 0xFF).toByte()
        priv.mlkem.copyInto(blob, 34)
        keyFile().apply { parentFile.mkdirs() }
            .writeBytes(JvmCryptoService().encryptBytes(blob, CryptoKey(RSA.public)))
        return keyPair
    }

    /** Unwrap the on-disk keyring and bind the resulting master key into the session scope. */
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
