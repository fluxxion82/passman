package ai.passman.platform.keyring

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.kdf.PasswordHasher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultFailure
import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.keystore.JvmKeyStoreClient
import ai.passman.keystore.KeystoreClient
import ai.passman.keystore.LowPbePkcs12Writer
import ai.passman.keystore.model.Keystore
import ai.passman.platform.crypto.JvmSecureRandomService
import ai.passman.platform.repository.LocalUserRepository
import ai.passman.platform.service.BioAuthService
import ai.passman.platform.service.JvmKeystoreLifecycle
import ai.passman.platform.service.KeystoreLifecycle
import ai.passman.platform.service.PgpKeyRingService
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.repo.di.toolsModule
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.KdfParams
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.Key
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe
import org.bouncycastle.asn1.pkcs.EncryptedData
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.Pfx
import org.bouncycastle.asn1.pkcs.SafeBag
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/** Generous: a parked login is waiting on another login's real Argon2id and real PKCS#12 re-key. */
private const val PARK_TIMEOUT_SECONDS = 60L

/** The alias every account's identity key sits under. Frozen: it is on disk. */
private const val IDENTITY_ALIAS = "passmanMain"

/**
 * The account-bootstrap and identity-store migration contract.
 *
 * These tests are the deliverable of the keyring change as much as the code is. The failure they
 * exist to prevent is not "login is slow" or "the file has the wrong name" — it is an account whose
 * PKCS#12 identity store is sealed with a password nobody holds, which is unrecoverable and silent.
 * So every test here asks the same question from a different starting state: **after this, does the
 * store still open with either the login password or the derived one?**
 *
 * Everything below the seams is real: a real `JvmKeyStoreClient` writing real PKCS#12 files, a real
 * `PasswordVaultCipher` running real Argon2id, the real `toolsModule` Koin graph the app uses. The
 * fakes are only the things that would otherwise need a device (biometrics), a keyring server (PGP),
 * or a slow second KDF that is not what is under test (the *credential* hasher — the keyring's own
 * Argon2id is real and is the one that matters).
 */
@OptIn(ExperimentalEncodingApi::class)
class KeyringBootstrapTest {

    private lateinit var root: File
    private lateinit var platform: Platform
    private lateinit var keystoreClient: KeystoreClient
    private lateinit var vaultCipher: VaultCipher
    private lateinit var hasher: CountingPasswordHasher
    private lateinit var prefs: FakePreferences
    private lateinit var storage: FakeStorage
    private lateinit var pgp: FakePgpKeyRingService

    private val user = "alice"
    private val loginPassword = "correct horse battery staple"
    private val newPassword = "a second correct horse"
    private val ringPassphrase = "a generated ring passphrase, never the login password"

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("keyring-bootstrap").toFile()
        platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        keystoreClient = JvmKeyStoreClient()
        hasher = CountingPasswordHasher()
        prefs = FakePreferences()
        storage = FakeStorage()
        pgp = FakePgpKeyRingService()

        startKoin {
            modules(
                toolsModule,
                module {
                    single<Platform> { platform }
                    single<KeystoreClient> { keystoreClient }
                },
            )
        }
        // Resolve through Koin so the tests exercise the same binding production does.
        vaultCipher = KoinPlatform.getKoin().get()
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        root.deleteRecursively()
    }

    // ---------------------------------------------------------------- signup

    @Test
    fun `signup creates an owner-only keyring and seals the identity store with the derived password`() = runBlocking<Unit> {
        val outcome = signup(repository())

        assertIs<Outcome.Success<AppUser>>(outcome)
        val keyring = keyringFile()
        assertTrue(keyring.isFile, "signup must create ${DirectoryBundler.KEYRING_FILE_NAME}")
        assertContentEquals(
            "PMKR".encodeToByteArray(),
            keyring.readBytes().copyOfRange(0, 4),
            "the keyring must be a PMKR envelope",
        )
        assertEquals(
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
            Files.getPosixFilePermissions(keyring.toPath()),
            "the keyring holds the device master key and must not be group- or world-readable",
        )

        val derived = derivedStorePassword(loginPassword)
        assertTrue(canOpenStore(derived), "the .pfx must open with the keyring-derived password")
        assertFalse(
            canOpenStore(loginPassword),
            "the .pfx must NOT open with the login password — that is the weak-KDF hole this closes",
        )
    }

    @Test
    fun `signup rolls back the keyring and the account directory when a later step fails`() = runBlocking<Unit> {
        pgp.failing = true

        val outcome = signup(repository())

        assertIs<Outcome.Error>(outcome)
        assertFalse(keyringFile().exists(), "a rolled-back signup must leave no keyring")
        assertFalse(identityStoreFile().exists(), "a rolled-back signup must leave no identity store")
        assertFalse(accountDirectory().exists(), "a rolled-back signup must leave no account directory")

        // And a retry starts clean rather than inheriting an unopenable store.
        pgp.failing = false
        assertIs<Outcome.Success<AppUser>>(signup(repository()))
        assertTrue(canOpenStore(derivedStorePassword(loginPassword)))
    }

    @Test
    fun `signup on an existing account refuses before touching the existing identity store`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))
        val storeBefore = identityStoreFile().readBytes()
        val keyringBefore = keyringFile().readBytes()

        val outcome = repository().signup(user, "a totally different password", "another ring passphrase")

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailureNames.ACCOUNT_ALREADY_EXISTS, outcome.cause::class.simpleName)
        assertContentEquals(storeBefore, identityStoreFile().readBytes(), "the live account's .pfx must be untouched")
        assertContentEquals(keyringBefore, keyringFile().readBytes(), "the live account's keyring must be untouched")
        assertTrue(canOpenStore(derivedStorePassword(loginPassword)), "the original account must still open")
    }

    /**
     * The vault database is not the account.
     *
     * Deleting the database and restoring a backup — the plan's own restore drill — leaves
     * `keystore/<user>/` untouched. Gating signup on `storage.exists` alone let a signup run in that
     * state: it minted a new master key, and `hybrid.key`, `mldsa.key` and the pre-existing `.pfx`
     * were orphaned under an identity nothing could reach. Task 6 hangs the PQ key files off the
     * master key, which turns "orphaned if you are unlucky" into "orphaned every time".
     */
    @Test
    fun `signup refuses an account whose database is gone but whose keystore survives`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))
        val keyringBefore = keyringFile().readBytes()
        val storeBefore = identityStoreFile().readBytes()
        val derived = derivedStorePassword(loginPassword)
        storage.delete(user)

        val keyringStillThere = repository().signup(user, "a totally different password", "another ring passphrase")

        assertIs<Outcome.Error>(keyringStillThere)
        assertEquals(AuthFailureNames.ACCOUNT_ALREADY_EXISTS, keyringStillThere.cause::class.simpleName)

        // And with the keyring gone too, the surviving .pfx alone must still be enough to refuse:
        // recreating the account would leave that store sealed under an RSA identity nothing holds.
        keyringFile().delete()
        val storeStillThere = repository().signup(user, "a totally different password", "another ring passphrase")

        assertIs<Outcome.Error>(storeStillThere)
        assertEquals(AuthFailureNames.ACCOUNT_ALREADY_EXISTS, storeStillThere.cause::class.simpleName)
        assertContentEquals(storeBefore, identityStoreFile().readBytes(), "the surviving .pfx must be untouched")

        // Restoring the keyring restores the account, proving neither refusal damaged anything.
        keyringFile().writeBytes(keyringBefore)
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
        assertTrue(canOpenStore(derived))
    }

    // ----------------------------------------------------------------- login

    @Test
    fun `login binds a vault session key and logout destroys it`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()

        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))
        val bound = assertNotNull(vaultSession().current, "login must bind a VaultSessionKey into the session scope")
        // Proves the key is live: deriving from it requires un-destroyed material.
        assertEquals(derivedStorePassword(loginPassword), vaultCipher.identityStorePassword(bound).value)

        repository.logout()

        val destroyed = assertFailsWith<IllegalStateException> { vaultCipher.identityStorePassword(bound) }
        assertTrue(
            destroyed.message.orEmpty().contains("destroyed"),
            "closing the session scope must zero the key material, was: ${destroyed.message}",
        )
    }

    @Test
    fun `login migrates a pre-keyring account onto the derived identity-store password`() = runBlocking<Unit> {
        legacyAccount()
        assertTrue(canOpenStore(loginPassword), "fixture precondition: the legacy store is on the login password")
        assertFalse(keyringFile().exists(), "fixture precondition: a legacy account has no keyring")

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        assertTrue(keyringFile().isFile, "the first login must create the keyring")
        assertTrue(canOpenStore(derivedStorePassword(loginPassword)), "the store must move onto the derived password")
        assertFalse(canOpenStore(loginPassword), "the login password must no longer open the store")
    }

    @Test
    fun `login resumes a migration interrupted between keyring creation and the store password change`() = runBlocking<Unit> {
        legacyAccount()
        // Exactly the crash window: the keyring is on disk, the store has not been re-keyed yet.
        val created = vaultCipher.createSession(loginPassword)
        KeyringStore(platform).write(user, created.keyringBytes)
        val derived = vaultCipher.identityStorePassword(created.sessionKey).value
        created.sessionKey.destroy()
        assertTrue(canOpenStore(loginPassword), "fixture precondition: the store is still on the login password")
        assertFalse(canOpenStore(derived), "fixture precondition: the store has not been re-keyed")

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        assertTrue(canOpenStore(derived), "the next login must complete the interrupted store password change")
        assertFalse(canOpenStore(loginPassword))
        assertContentEquals(
            created.keyringBytes,
            keyringFile().readBytes(),
            "resuming must reuse the existing keyring, not mint a second master key",
        )
    }

    @Test
    fun `login survives a failing store password change and retries on the next login`() = runBlocking<Unit> {
        legacyAccount()
        val lifecycle = FlakyKeystoreLifecycle(JvmKeystoreLifecycle(keystoreClient))
        lifecycle.failChangePassword = true

        assertIs<Outcome.Success<AppUser>>(repository(keystoreLifecycle = lifecycle).login(user, loginPassword))

        // Not half-applied: the store is exactly where it started, and the account is usable.
        assertTrue(canOpenStore(loginPassword), "a failed migration must leave the store on the login password")
        assertFalse(canOpenStore(derivedStorePassword(loginPassword)))
        assertTrue(keyringFile().isFile, "the keyring is written first and stays")

        lifecycle.failChangePassword = false
        assertIs<Outcome.Success<AppUser>>(repository(keystoreLifecycle = lifecycle).login(user, loginPassword))

        assertTrue(canOpenStore(derivedStorePassword(loginPassword)), "the retry must complete the migration")
        assertFalse(canOpenStore(loginPassword))
    }

    @Test
    fun `login performs exactly two memory-hard derivations`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()

        // The keyring's Argon2id lives inside KeyringEnvelope, which owns a private JvmPasswordHasher
        // and is not reachable through the injected PasswordHasher. So the two derivations are counted
        // at the two seams that actually perform them: the credential hasher, and the vault cipher.
        val counting = CountingVaultCipher(vaultCipher)
        hasher.reset()

        assertIs<Outcome.Success<AppUser>>(repository(vaultCipher = counting).login(user, loginPassword))

        assertEquals(1, hasher.deriveCount, "credential verification is the only injected-hasher derivation")
        assertEquals(1, counting.unlockCount, "the keyring is unwrapped exactly once")
        assertEquals(0, counting.createCount, "an existing keyring is never re-created")
    }

    @Test
    fun `login with a corrupt keyring fails without touching the identity store`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))
        repository().logout()
        val storeBefore = identityStoreFile().readBytes()
        keyringFile().writeBytes(keyringFile().readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })

        val outcome = repository().login(user, loginPassword)

        assertIs<Outcome.Error>(outcome)
        assertContentEquals(storeBefore, identityStoreFile().readBytes(), "a keyring failure must not re-key the store")
        assertNull(vaultSession().current, "no session key may be bound after a failed unlock")
    }

    @Test
    fun `login with the wrong password never reaches the keyring`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))
        repository().logout()
        val counting = CountingVaultCipher(vaultCipher)

        val outcome = repository(vaultCipher = counting).login(user, "not the password")

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailureNames.INVALID_PASSWORD, outcome.cause::class.simpleName)
        assertEquals(0, counting.unlockCount, "a wrong password must be rejected before any keyring work")
    }

    // --------------------------------------------------- two logins at once

    /**
     * Two first logins on one pre-keyring account, interleaved at the point where it hurts.
     *
     * Login A is parked *inside* `KeyringRepository.read`, holding the answer "no keyring". Login B
     * then runs to completion: it mints its own master key, writes the keyring, and re-keys the
     * `.pfx` onto the password derived from it. A is released and resumes with its stale answer.
     *
     * Without a guard, A mints a second master key and overwrites B's keyring. The end state is
     * `keyring = K_A`, `.pfx = derived(K_B)`, and the key that opens the store existing nowhere —
     * from two logins that both returned `Success`. The desktop app has no single-instance lock, so
     * this is a double-click, not a thought experiment. The sequential tests in this class cannot
     * see it at all.
     */
    @Test
    fun `a login parked inside the keyring read cannot overwrite a keyring another login minted`() = runBlocking<Unit> {
        legacyAccount()
        val reachedTheParkingSpot = CountDownLatch(1)
        val winnerFinished = CountDownLatch(1)
        val parking = ParkingKeyringRepository(
            delegate = KeyringStore(platform),
            parkOn = ParkPoint.READ,
            reached = reachedTheParkingSpot,
            release = winnerFinished,
        )

        val loser = FutureTask { runBlocking { repository(keyringRepository = parking).login(user, loginPassword) } }
        Thread(loser, "parked-login").start()
        assertTrue(
            reachedTheParkingSpot.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS),
            "the parked login never reached KeyringRepository.read",
        )

        val winner = repository().login(user, loginPassword)

        assertIs<Outcome.Success<AppUser>>(winner)
        val winningKeyring = keyringFile().readBytes()
        val winningStorePassword = derivedStorePassword(loginPassword)
        assertTrue(canOpenStore(winningStorePassword), "the winner must have migrated the store")

        winnerFinished.countDown()
        val loserOutcome = loser.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertIs<Outcome.Error>(loserOutcome)
        assertContentEquals(
            winningKeyring,
            keyringFile().readBytes(),
            "the resuming login must not replace the keyring the other login already migrated onto",
        )
        assertTrue(canOpenStore(winningStorePassword), "the identity store must still open")
        // And the account is not merely intact on disk — it still signs in.
        repository().logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
    }

    /**
     * The same race, moved past the guard.
     *
     * Login A is parked *after* it decided minting was safe and *before* it writes, which is the one
     * interleaving the store-state check cannot catch: both logins legitimately observed an
     * un-migrated account. Only the `O_EXCL` claim inside `createNew` can separate them, and the
     * loser has to find out and drop the master key it was holding rather than write it out.
     */
    @Test
    fun `a login that loses the keyring creation race discards its master key`() = runBlocking<Unit> {
        legacyAccount()
        val reachedTheParkingSpot = CountDownLatch(1)
        val winnerFinished = CountDownLatch(1)
        val parking = ParkingKeyringRepository(
            delegate = KeyringStore(platform),
            parkOn = ParkPoint.CREATE_NEW,
            reached = reachedTheParkingSpot,
            release = winnerFinished,
        )

        val loser = FutureTask { runBlocking { repository(keyringRepository = parking).login(user, loginPassword) } }
        Thread(loser, "parked-mint").start()
        assertTrue(
            reachedTheParkingSpot.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS),
            "the parked login never reached KeyringRepository.createNew",
        )

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
        val winningKeyring = keyringFile().readBytes()
        val winningStorePassword = derivedStorePassword(loginPassword)

        winnerFinished.countDown()
        val loserOutcome = loser.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertIs<Outcome.Error>(loserOutcome)
        assertContentEquals(
            winningKeyring,
            keyringFile().readBytes(),
            "createNew must refuse the second writer rather than let it clobber the first",
        )
        assertTrue(canOpenStore(winningStorePassword))
        repository().logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
    }

    /**
     * The store-state guard on its own, with the `O_EXCL` claim unable to help.
     *
     * Here the keyring is genuinely gone — a partial restore of `keystore/<user>/`, a user tidying
     * up a file they did not recognise — while the `.pfx` is still on the password derived from the
     * master key it held. `createNew` cannot object: there is no file to collide with. Only the
     * question "does this store open with the login password?" separates this from the ordinary
     * pre-keyring first login, and getting it wrong means writing a master key the `.pfx` will never
     * accept over the exact spot the user's backup has to be restored to.
     */
    @Test
    fun `a login refuses to mint a keyring when the identity store is already on a derived password`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        val goodKeyring = keyringFile().readBytes()
        val derived = derivedStorePassword(loginPassword)
        val storeBefore = identityStoreFile().readBytes()
        assertTrue(keyringFile().delete(), "fixture precondition: the keyring is gone")

        val outcome = repository().login(user, loginPassword)

        assertIs<Outcome.Error>(outcome)
        assertFalse(
            keyringFile().exists(),
            "minting here installs a master key the .pfx will never accept, on top of where the backup goes",
        )
        assertContentEquals(storeBefore, identityStoreFile().readBytes(), "the identity store must be untouched")

        // Restoring the backup is all it takes, because nothing was written over it.
        keyringFile().writeBytes(goodKeyring)
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
        assertTrue(canOpenStore(derived))
    }

    /**
     * A zero-length `keyring.pmk` on an account that has already migrated.
     *
     * `KeyringStore.read` reports zero length as "no keyring" on purpose, so the bootstrap path sees
     * exactly what it sees for a pre-keyring account — and used to respond the same way, minting a
     * fresh master key straight over it. The `.pfx` is on a password derived from the *old* master
     * key, so that write is the account's death certificate, and it happened before anything had
     * asked the store a single question.
     */
    @Test
    fun `a zero-length keyring on a migrated account is refused rather than replaced`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        val goodKeyring = keyringFile().readBytes()
        val derived = derivedStorePassword(loginPassword)
        val storeBefore = identityStoreFile().readBytes()

        keyringFile().writeBytes(ByteArray(0))

        val outcome = repository().login(user, loginPassword)

        assertIs<Outcome.Error>(outcome)
        assertEquals(
            0L,
            keyringFile().length(),
            "a fresh master key must not be minted over a keyring whose store is already derived",
        )
        assertContentEquals(storeBefore, identityStoreFile().readBytes(), "the identity store must be untouched")

        // Nothing was destroyed: putting the real keyring back brings the account straight home,
        // which is impossible if a new master key had been written over it.
        keyringFile().writeBytes(goodKeyring)
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
        assertTrue(canOpenStore(derived))
    }

    // ------------------------------------------------------------ kdf upgrade

    /**
     * The KDF upgrade must survive the caller's own upsert.
     *
     * `LoginUser` upserts the `AppUser` the repository returns. Returning the *pre-upgrade*
     * credential made that upsert write the legacy PBKDF2 record straight back over the Argon2id
     * one `maybeUpgradeKdf` had just persisted — so every login verified at the legacy KDF's full
     * cost and re-ran the upgrade, forever. The returned credential is the fix's whole surface,
     * which is why every assertion here is about what the caller receives and what a *second*
     * login then does.
     */
    @Test
    fun `login returns the upgraded credential so the caller's upsert cannot undo the KDF upgrade`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        // A true legacy record: derived under PBKDF2 and carrying no KDF params at all.
        val legacySalt = ByteArray(48) { (it + 1).toByte() }
        prefs.credentials[user] = Password(
            hash = Base64.Mime.encode(hasher.derive(loginPassword, legacySalt, KdfParams.LEGACY_PBKDF2)),
            salt = Base64.Mime.encode(legacySalt),
            kdf = null,
        )

        val outcome = repository().login(user, loginPassword)

        assertIs<Outcome.Success<AppUser>>(outcome)
        val returned = assertIs<AppUser.LoggedIn>(outcome.value)
        assertEquals(
            KdfParams.ARGON2ID_DEFAULT,
            returned.password.kdf,
            "login must hand the caller the upgraded credential, not the legacy one it verified against",
        )
        assertEquals(KdfParams.ARGON2ID_DEFAULT, prefs.credentials.getValue(user).kdf, "the upgrade must persist")

        // Exactly what LoginUser does with the returned value — this upsert was the clobber.
        prefs.upsert(outcome.value)
        assertEquals(
            KdfParams.ARGON2ID_DEFAULT,
            prefs.credentials.getValue(user).kdf,
            "the caller's upsert of the returned credential must not resurrect the legacy record",
        )

        // And the account has actually converged: the next login verifies once under the current
        // KDF and does not re-derive. A clobbered credential re-fires the upgrade here (2 derives).
        repository().logout()
        hasher.reset()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))
        assertEquals(1, hasher.deriveCount, "an already-upgraded credential must not be re-derived on login")
    }

    // ------------------------------------------------------- session plumbing

    @Test
    fun `the session RSA key handles resolve under the frozen qualifiers after migration`() = runBlocking<Unit> {
        legacyAccount()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        // SyncTlsProvider resolves PRIVATE_DECRYPTION_KEY (the raw java.security.Key) and
        // JvmFingerprintService resolves PUBLIC_ENCRYPTION_KEY_HANDLE, both by qualifier and both
        // without parameters. Only the *source* of the password argument changed, so both must still
        // resolve from the instances login warmed.
        val scope = sessionScope()
        assertNotNull(scope.getOrNull<Key>(named(PRIVATE_DECRYPTION_KEY)), "SyncTlsProvider's lookup must still work")
        assertNotNull(scope.get<CryptoKey>(named(PUBLIC_ENCRYPTION_KEY_HANDLE)).encoded)
        assertNotNull(scope.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)))
    }

    @Test
    fun `the keyring is excluded from sync bundles`() {
        assertTrue(
            DirectoryBundler.KEYRING_FILE_NAME in DirectoryBundler.syncExclusions(user),
            "the keyring is device identity and must never be bundled into a sync payload",
        )
    }

    // ------------------------------------------------------- password change

    @Test
    fun `changing the password rewraps only the keyring`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        // Sentinels for the two PQ key files. They are still RSA-wrapped at this point (Task 6 moves
        // them onto keyring subkeys) and a password change must not so much as open them, so inert
        // bytes prove exactly the property under test: nothing in keystore/<user>/ is rewritten
        // except the keyring itself.
        val hybridKey = File(accountDirectory(), "hybrid.key").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val mldsaKey = File(accountDirectory(), "mldsa.key").apply { writeBytes(byteArrayOf(4, 5, 6)) }
        val storeBefore = identityStoreFile().readBytes()
        val vaultBefore = storage.read(user)
        val keyringBefore = keyringFile().readBytes()
        val derivedBefore = derivedStorePassword(loginPassword)

        val outcome = repository.changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Success<AppUser>>(outcome)
        prefs.upsert(outcome.value) // the ChangeUserPassword use case persists the new credential
        assertContentEquals(storeBefore, identityStoreFile().readBytes(), "the .pfx must be byte-identical")
        assertContentEquals(vaultBefore, storage.read(user), "the vault DB must be byte-identical")
        assertContentEquals(byteArrayOf(1, 2, 3), hybridKey.readBytes(), "hybrid.key must be byte-identical")
        assertContentEquals(byteArrayOf(4, 5, 6), mldsaKey.readBytes(), "mldsa.key must be byte-identical")
        assertFalse(keyringBefore.contentEquals(keyringFile().readBytes()), "the keyring must be rewrapped")
        assertFalse(stagedKeyringFile().exists(), "a completed change leaves no staged generation behind")

        // The master key did not rotate, so the store password is unchanged and the store still opens.
        val session = vaultCipher.unlockSession(keyringFile().readBytes(), newPassword)
        assertEquals(derivedBefore, vaultCipher.identityStorePassword(session).value)
        session.destroy()
        assertTrue(canOpenStore(derivedBefore))
        assertFailsWith<VaultFailure.WrongPassword> { vaultCipher.unlockSession(keyringFile().readBytes(), loginPassword) }

        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, newPassword))
        assertIs<Outcome.Error>(repository().login(user, loginPassword))
    }

    // --------------------------- pgp ring passphrase decoupling (Task 7)

    @Test
    fun `signup seals the pgp rings with the provided passphrase, not the login password`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))

        val (userId, passphrase) = pgp.createCalls.single()
        assertEquals(user, userId)
        assertEquals(ringPassphrase, passphrase)
        assertNotEquals(loginPassword, passphrase, "a cracked ring file must not yield the vault login")
    }

    /**
     * The must-check interaction from the release-polish plan: a master-password change re-wraps
     * `keyring.pmk` and nothing else, so rings whose passphrase is not the login password cannot
     * break it. What this proves is service-level, not byte-level: the fake ring service writes no
     * files, so the assertion is that neither the change nor the following login ever re-invokes
     * it (the byte-identity of everything under `keystore/<user>/` is covered by "changing the
     * password rewraps only the keyring"). The change succeeds and the new password logs in with
     * the rings never revisited.
     */
    @Test
    fun `changing the password never re-invokes the pgp ring service`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))

        assertIs<Outcome.Success<AppUser>>(repository.changeUserPassword(loginPassword, newPassword))

        assertEquals(listOf(user to ringPassphrase), pgp.createCalls, "the change must not ask for any ring work")
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, newPassword))
        assertEquals(1, pgp.createCalls.size, "login must not revisit the ring service either")
    }

    /**
     * The change commits the credential itself, because the promotion has to happen *after* it.
     *
     * `ChangeUserPassword` (the use case) upserts what this returns, but that upsert lands after the
     * repository has already returned — far too late to order the keyring promotion against. Leaving
     * the credential to the caller is precisely what opened the window this two-generation scheme
     * closes, so the repository owns both halves and the caller's upsert becomes a harmless repeat.
     */
    @Test
    fun `changing the password persists the new credential itself`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val before = prefs.credentials.getValue(user)

        assertIs<Outcome.Success<AppUser>>(repository.changeUserPassword(loginPassword, newPassword))

        assertNotEquals(before.hash, prefs.credentials.getValue(user).hash, "the credential must already be on disk")
    }

    // ------------------------------------- password change: the crash window

    /**
     * Crash between staging the rewrapped keyring and committing the credential.
     *
     * Nothing has committed yet, so the change simply did not happen: the credential and the live
     * keyring are both still on the old password. The staged generation is debris, and the login that
     * finds the live keyring opening normally has to remove it — a `.next` that outlives its change
     * would be promoted by some later login and take the account's live keyring with it.
     */
    @Test
    fun `a crash before the credential commits leaves the old password working`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        stageChangeTo(newPassword) // crash lands here: `.next` written, credential untouched

        assertIs<Outcome.Error>(repository().login(user, newPassword), "the change never committed")
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword), "the old password must open the account")
        assertFalse(stagedKeyringFile().exists(), "a stale staged generation must not survive a successful login")
        assertTrue(canOpenStore(derivedStorePassword(loginPassword)))
    }

    /**
     * Crash between committing the credential and promoting the staged keyring — the state the old
     * single-generation flow could not survive.
     *
     * With one keyring the credential would say "new password" while the only keyring on disk still
     * wanted the old one: `verifiedCredentials(old)` fails, and `unlockSession(keyring, new)` fails
     * too. **Neither password opens the account.** The staged generation is what makes it recoverable:
     * the new password verifies, the live keyring refuses it, and the pending one accepts it.
     */
    @Test
    fun `a crash after the credential commits completes the change on the next login`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        val staged = stageChangeTo(newPassword)
        prefs.upsert(AppUser.LoggedIn(user, credentialFor(newPassword))) // credential committed, then crash

        assertIs<Outcome.Error>(repository().login(user, loginPassword), "the change committed; the old password is gone")
        assertIs<Outcome.Success<AppUser>>(repository().login(user, newPassword))

        assertContentEquals(staged, keyringFile().readBytes(), "the pending generation must be promoted, not discarded")
        assertFalse(stagedKeyringFile().exists(), "promotion must consume the staged generation")
        assertTrue(canOpenStore(derivedStorePassword(newPassword)), "the identity store is untouched by any of this")

        // And it stays completed: a second login finds an ordinary account.
        repository().logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, newPassword))
    }

    /**
     * The live keyring gone and only the pending generation left — a promotion interrupted by a
     * filesystem that lost the directory entry, or a partial restore. `createNew`'s O_EXCL claim
     * cannot help here and the mint path would install a master key the `.pfx` never accepts, so the
     * pending generation has to be consulted before minting is even considered.
     */
    @Test
    fun `a login recovers when only the staged generation survives`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        val derived = derivedStorePassword(loginPassword)
        val staged = stageChangeTo(newPassword)
        prefs.upsert(AppUser.LoggedIn(user, credentialFor(newPassword)))
        assertTrue(keyringFile().delete(), "fixture precondition: the live keyring is gone")

        assertIs<Outcome.Success<AppUser>>(repository().login(user, newPassword))

        assertContentEquals(staged, keyringFile().readBytes())
        assertFalse(stagedKeyringFile().exists())
        assertTrue(canOpenStore(derived), "the master key never rotated, so the store password never changed")
    }

    /** A staged generation the current password cannot open is debris, and must never be promoted. */
    @Test
    fun `a staged generation that does not open is not promoted`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        repository.logout()
        val live = keyringFile().readBytes()
        KeyringStore(platform).writeNext(user, vaultCipher.createSession("an unrelated password").keyringBytes)

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        assertContentEquals(live, keyringFile().readBytes(), "an unopenable staged generation must not replace the keyring")
        assertFalse(stagedKeyringFile().exists(), "and it must be cleared away")
    }

    @Test
    fun `a failed change removes the staged generation and leaves the old password working`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val keyringBefore = keyringFile().readBytes()

        val outcome = repository.changeUserPassword("not the current password", newPassword)

        assertIs<Outcome.Error>(outcome)
        assertFalse(stagedKeyringFile().exists())
        assertContentEquals(keyringBefore, keyringFile().readBytes())
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))
    }

    /**
     * A concurrent login racing the promotion — the two-generation scheme's own failure mode.
     *
     * A login that finds the live keyring opening normally treats a staged generation as debris and
     * removes it, which is right for an abandoned change and catastrophic for one that is mid-flight:
     * land between the credential commit and the promotion and the change is left with a credential
     * on the new password and a keyring on the old, which is the both-passwords-fail state arrived at
     * from the opposite direction. `promoteNext` sees nothing to promote and says so, and without a
     * confirmation step that report goes nowhere.
     *
     * The decorator below is the deleting login, compressed to the one action that matters and
     * injected at the exact instant it would occur.
     */
    @Test
    fun `a change whose staged generation is deleted before promotion still lands`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val store = KeyringStore(platform)
        val racing = object : KeyringRepository by store {
            private val armed = AtomicBoolean(true)
            override fun promoteNext(username: String): Boolean {
                // Exactly what a concurrent login's "remove the stale staged generation" does, and
                // once, because that login only happens once.
                if (armed.compareAndSet(true, false)) store.deleteNext(username)
                return store.promoteNext(username)
            }
        }

        val outcome = repository(keyringRepository = racing).changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Success<AppUser>>(outcome)
        assertFalse(stagedKeyringFile().exists())
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, newPassword), "the new password must open the account")
        assertIs<Outcome.Error>(repository().login(user, loginPassword))
    }

    /**
     * The same race, but the staged generation cannot be put back either.
     *
     * There is then nothing to promote and no way to make one, so the only state left that anybody
     * can open is the one the account started in: keyring on the old password, credential put back to
     * match. Reporting success here would hand the user a password that opens nothing.
     */
    @Test
    fun `a change that cannot promote restores the previous credential`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val keyringBefore = keyringFile().readBytes()
        val store = KeyringStore(platform)
        val hostile = object : KeyringRepository by store {
            override fun promoteNext(username: String): Boolean = store.deleteNext(username)
            override fun writeNext(username: String, bytes: ByteArray) {
                if (store.readNext(username) != null) throw IllegalStateException("simulated staging failure")
                store.writeNext(username, bytes)
            }
        }

        val outcome = repository(keyringRepository = hostile).changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Error>(outcome)
        assertContentEquals(keyringBefore, keyringFile().readBytes(), "the live keyring must be exactly as it was")
        assertFalse(stagedKeyringFile().exists())
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword), "the old password must still work")
        assertIs<Outcome.Error>(repository().login(user, newPassword))
    }

    /**
     * The rollback's own failure mode: two password changes at once.
     *
     * A rival change commits its credential and promotes its keyring inside this change's
     * confirmation gap. This change is then correct to conclude it failed — the live keyring is not
     * its staged one — but the credential on disk is no longer the one it wrote, it is the rival's,
     * and it matches the rival's keyring exactly. Restoring the *previous* credential over that
     * strands all three passwords at once: the old one has no keyring, this change's new one has no
     * keyring, and the rival's password is the one just overwritten.
     *
     * So the rollback re-reads the credential and only restores while it is still the one this flow
     * committed. Here it is not, so it must leave it alone and the rival's password must still work.
     */
    @Test
    fun `a change that loses to a concurrent change does not overwrite the rival credential`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val rivalPassword = "the other change's password"
        val store = KeyringStore(platform)
        // The rival, compressed to the facts that matter and injected at the exact instant they would
        // land: it commits its own credential and promotes its own keyring inside this change's
        // confirmation gap, and — being a change that is still running — it goes on clearing this
        // one's staged generation, so both attempts lose the same way.
        val rival = object : KeyringRepository by store {
            private val armed = AtomicBoolean(true)
            override fun promoteNext(username: String): Boolean {
                if (armed.compareAndSet(true, false)) {
                    val session = vaultCipher.unlockSession(store.read(username)!!, loginPassword)
                    val rivalKeyring = try {
                        vaultCipher.rewrapSession(session, rivalPassword)
                    } finally {
                        session.destroy()
                    }
                    store.write(username, rivalKeyring)
                    prefs.credentials[user] = credentialFor(rivalPassword)
                    prefs.user = AppUser.LoggedIn(user, prefs.credentials.getValue(user))
                }
                store.deleteNext(username)
                return false
            }
        }

        val outcome = repository(keyringRepository = rival).changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Error>(outcome)
        assertEquals(
            credentialFor(rivalPassword).hash,
            prefs.credentials.getValue(user).hash,
            "the losing change must not write its own rollback over the credential the rival committed",
        )
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(
            repository().login(user, rivalPassword),
            "the rival's password must still open the account",
        )
        assertFalse(stagedKeyringFile().exists(), "and that login clears the loser's staged generation")
        assertIs<Outcome.Error>(repository().login(user, loginPassword))
        assertIs<Outcome.Error>(repository().login(user, newPassword))
    }

    /**
     * The same guard reached without any race at all.
     *
     * The promotion fails, so the credential has to go back — and the write that puts it back fails
     * too. The credential is therefore still on the *new* password, and the only keyring that opens
     * with it is the staged generation `promoteAndConfirm` re-staged a moment ago. Deleting that
     * because "the change failed" leaves neither password working, from a single flow, with no
     * concurrency needed to reach it.
     *
     * So the staged generation is discarded only once the credential is demonstrably back.
     */
    @Test
    fun `a change whose credential rollback fails keeps the staged keyring that still opens`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val store = KeyringStore(platform)
        val neverPromotes = object : KeyringRepository by store {
            override fun promoteNext(username: String): Boolean {
                store.deleteNext(username)
                return false
            }
        }
        // Fail exactly the rollback's write and nothing else: the rollback is the only upsert that
        // puts the *original* credential back, and it runs after the commit has already replaced it.
        val original = prefs.credentials.getValue(user)
        prefs.failUpsertWhen = { it is AppUser.LoggedIn && it.password == original }

        val outcome = repository(keyringRepository = neverPromotes).changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Error>(outcome)
        prefs.failUpsertWhen = { false }
        assertTrue(
            stagedKeyringFile().isFile,
            "the credential is still on the new password; the staged keyring is the only thing that opens it",
        )

        // And that is not a technicality — the account really does still sign in.
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, newPassword))
        assertFalse(stagedKeyringFile().exists(), "and the login that resumes it consumes the staged generation")
    }

    /**
     * The promotion landed and only the confirming read could not be performed.
     *
     * The confirmation is a disk read, and a disk read can fail on its own — an unreadable directory
     * entry, a permissions change, a volume that went away for a moment. Letting that throw abandoned
     * `changeUserPassword` by exception at the one point where the change *had already succeeded*: the
     * caller saw a crash, and the rollback decision was skipped entirely, so nothing even tried to
     * work out which state the account was in.
     *
     * `promoteNext` reporting true settles it. The staged generation is gone because it became the
     * live keyring, so the account is on the new password; rolling the credential back would move it
     * onto one the live keyring no longer accepts.
     */
    @Test
    fun `a change whose confirming read fails after a successful promotion is reported as success`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val store = KeyringStore(platform)
        val unreadable = object : KeyringRepository by store {
            var live = true
            override fun read(username: String): ByteArray? =
                if (live) throw java.io.IOException("simulated keyring read failure") else store.read(username)
        }

        val outcome = repository(keyringRepository = unreadable).changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Success<AppUser>>(outcome)
        unreadable.live = false
        assertFalse(stagedKeyringFile().exists(), "the promotion really did consume the staged generation")

        // The account is on the new password, which is what reporting success claimed.
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository().login(user, newPassword))
        assertIs<Outcome.Error>(repository().login(user, loginPassword))
    }

    /**
     * The caller walks away mid-change — the shipped bug, reproduced.
     *
     * `SettingsViewModel` launched the change in `viewModelScope`, so logging out cleared the back
     * stack, the ViewModel was destroyed and the job was cancelled somewhere in the middle of the
     * two-file change. The cancellation surfaced at the credential write, which is a suspending
     * preferences write on a device and is stood in for here by a `yield` for the same reason a
     * crash is not simulated by killing a thread: what matters is that the flow reaches a
     * cancellable suspension point while the staged keyring is on disk. `runCatching` then caught the
     * `JobCancellationException` as though the write had failed, discarded the staged generation, and
     * returned an error to a screen that no longer existed. Nothing was corrupted and nothing was
     * changed — the user was simply told their master password had changed when it had not.
     *
     * So the section from staging to promotion runs under `NonCancellable`, and the assertion is not
     * about the return value (the cancelled caller never sees one) but about the account: the new
     * password opens it and the old one does not.
     */
    @Test
    fun `a change whose caller is cancelled after staging still lands`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val store = KeyringStore(platform)
        val staged = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        // Holds the change open at the exact instant the bug needs: the staged generation is on disk
        // and nothing has been committed against it yet.
        val announcing = object : KeyringRepository by store {
            override fun writeNext(username: String, bytes: ByteArray) {
                store.writeNext(username, bytes)
                staged.countDown()
                check(cancelled.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "the caller was never cancelled" }
            }
        }
        val suspendingPrefs = object : UserPreferences by prefs {
            override suspend fun upsert(user: AppUser) {
                yield() // a real credential write suspends; a cancelled caller finds out here
                prefs.upsert(user)
            }
        }
        val changing = repository(keyringRepository = announcing, userPreferences = suspendingPrefs)

        val job = launch(Dispatchers.IO) { changing.changeUserPassword(loginPassword, newPassword) }
        check(staged.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "the change never staged a keyring" }
        job.cancel() // the user logged out: exactly what clearing the back stack does to viewModelScope
        cancelled.countDown()
        job.join()

        assertFalse(stagedKeyringFile().exists(), "the staged generation must have been promoted, not discarded")
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(
            repository().login(user, newPassword),
            "the change was underway when its caller died; it must still have completed",
        )
        assertIs<Outcome.Error>(repository().login(user, loginPassword), "the old password must no longer open the account")
    }

    @Test
    fun `the staged keyring generation is excluded from sync bundles`() {
        assertTrue(
            DirectoryBundler.KEYRING_STAGED_FILE_NAME in DirectoryBundler.syncExclusions(user),
            "a pending keyring generation is device identity exactly like the live one",
        )
    }

    @Test
    fun `changing the password rejects a wrong current password`() = runBlocking<Unit> {
        val repository = repository()
        assertIs<Outcome.Success<AppUser>>(signup(repository))
        val keyringBefore = keyringFile().readBytes()

        val outcome = repository.changeUserPassword("not the current password", newPassword)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailureNames.INVALID_PASSWORD, outcome.cause::class.simpleName)
        assertContentEquals(keyringBefore, keyringFile().readBytes(), "a rejected change must not rewrap the keyring")
        assertFailsWith<VaultFailure.WrongPassword> { vaultCipher.unlockSession(keyringFile().readBytes(), newPassword) }
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword), "the old password must still work")
    }

    @Test
    fun `changing the password aborts when the identity store cannot be moved onto the derived password`() = runBlocking<Unit> {
        legacyAccount()
        val lifecycle = FlakyKeystoreLifecycle(JvmKeystoreLifecycle(keystoreClient))
        val repository = repository(keystoreLifecycle = lifecycle)
        lifecycle.failChangePassword = true
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))
        val keyringBefore = keyringFile().readBytes()

        val outcome = repository.changeUserPassword(loginPassword, newPassword)

        assertIs<Outcome.Error>(outcome)
        assertContentEquals(
            keyringBefore,
            keyringFile().readBytes(),
            "aborting must leave the keyring on the old password — the old password still opens the account",
        )
        // The account is exactly where it was: old password in, store on the login password.
        lifecycle.failChangePassword = true
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))
    }

    // ------------------------------------------------- identity store PBE parameters

    /**
     * Login opens the `.pfx`, and opening a PKCS#12 pays its PBE and MAC iteration counts in full,
     * every time. The JCA writers put six-figure counts on that file — BouncyCastle's 600,000 for the
     * certificate bags and a 1,200,000-iteration SHA-1 MAC — which is seconds of a phone's login.
     *
     * Those counts buy exactly one thing: expensive password guessing. The store's password is 256
     * bits of HKDF output from the device master key, so there is nothing to guess and nothing to buy.
     * That argument holds for this file and no other, which is why the last two tests in this section
     * are the ones that matter: the cheap parameters must never reach a store a person's password
     * opens.
     */
    @Test
    fun `signup writes an identity store at the low iteration count and login still opens it`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))

        assertLowPbeParameters(identityStoreFile().readBytes())
        val repository = repository()
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))
        assertTrue(canOpenStore(derivedStorePassword(loginPassword)), "the low-parameter store must still open")
    }

    @Test
    fun `migrating a pre-keyring account leaves it on the derived password at the low iteration count`() = runBlocking<Unit> {
        legacyAccount()
        val legacyAliases = storeAliases(loginPassword)
        assertTrue(
            LowPbePkcs12Writer.hasLegacyPbe(identityStoreFile().readBytes()),
            "fixture precondition: a pre-keyring store carries the JCA writer's expensive parameters",
        )

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        val derived = derivedStorePassword(loginPassword)
        assertTrue(canOpenStore(derived), "the migration must land on the derived password")
        assertLowPbeParameters(identityStoreFile().readBytes())
        assertEquals(legacyAliases, storeAliases(derived), "the migration must not lose an entry")
    }

    /**
     * The state both real devices are in: already on the derived password, but moved there by the JCA
     * writer, so still carrying its parameters. Nothing about the account is wrong — it is just slow —
     * so the fix is a one-time rewrite on the next login, and it has to be exactly one.
     */
    @Test
    fun `login re-encodes an already-migrated store that still carries the old parameters, once`() = runBlocking<Unit> {
        val derived = alreadyMigratedWithLegacyParameters()
        val keyBefore = identityKeyMaterial(derived)
        val aliasesBefore = storeAliases(derived)

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        assertLowPbeParameters(identityStoreFile().readBytes())
        assertTrue(canOpenStore(derived), "the re-encoded store must still open with the derived password")
        assertEquals(aliasesBefore, storeAliases(derived), "the re-encode must not lose an entry")
        assertContentEquals(
            keyBefore,
            identityKeyMaterial(derived),
            "the re-encode must move the SAME RSA identity across, not mint a new one",
        )

        // And it is a one-off: the second login finds nothing to do, and does nothing. A rewrite
        // re-salts PBKDF2, so any rewrite at all changes every byte of the file.
        val settled = identityStoreFile().readBytes()
        val repository = repository()
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))
        assertContentEquals(settled, identityStoreFile().readBytes(), "a second login must not rewrite the store again")
    }

    /**
     * **The invariant.** Everything else in this section is a performance change; this one is the
     * reason the performance change is allowed to exist.
     */
    @Test
    fun `a store still sealed with the login password is never re-encoded`() = runBlocking<Unit> {
        legacyAccount()
        // A failed migration is the reachable way to arrive here: the keyring exists, but the store
        // is still on the login password and login carries on with it.
        val lifecycle = FlakyKeystoreLifecycle(JvmKeystoreLifecycle(keystoreClient))
        lifecycle.failChangePassword = true
        val before = identityStoreFile().readBytes()

        assertIs<Outcome.Success<AppUser>>(repository(keystoreLifecycle = lifecycle).login(user, loginPassword))

        assertTrue(canOpenStore(loginPassword), "fixture: the failed migration leaves the store on the login password")
        assertContentEquals(
            before,
            identityStoreFile().readBytes(),
            "A store on the login password is guessable, and its PKCS#12 iteration count is the only thing " +
                "that makes guessing it expensive. Re-encoding this file at ${LowPbePkcs12Writer.ITERATIONS} " +
                "iterations would be the app performing a KDF downgrade on its own user. The cheap count is " +
                "sound ONLY for the 256-bit keyring-derived password — never for one a person chose.",
        )
    }

    @Test
    fun `a failing re-encode does not fail the login and is retried on the next one`() = runBlocking<Unit> {
        val derived = alreadyMigratedWithLegacyParameters()
        val lifecycle = FlakyKeystoreLifecycle(JvmKeystoreLifecycle(keystoreClient))
        lifecycle.failReencode = true
        val before = identityStoreFile().readBytes()

        assertIs<Outcome.Success<AppUser>>(repository(keystoreLifecycle = lifecycle).login(user, loginPassword))

        assertContentEquals(before, identityStoreFile().readBytes(), "a failed re-encode must leave the store alone")
        assertTrue(canOpenStore(derived), "and the account must be entirely usable")

        lifecycle.failReencode = false
        val repository = repository(keystoreLifecycle = lifecycle)
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))

        assertLowPbeParameters(identityStoreFile().readBytes())
        assertTrue(canOpenStore(derived))
    }

    // ------------------------------------------------- crash recovery from the commit backup

    /**
     * The one state an identity-store commit cannot undo for itself, and the login that finishes it.
     *
     * A commit builds the replacement beside the store and swaps it in with `DurableFiles.replace`.
     * Where the filesystem cannot promise an atomic move that degrades to a copy, so a failure part
     * way through leaves a truncated `.pfx`; the commit puts its backup straight back, and if *that*
     * fails too it strands the backup on purpose and returns the error — a `<user>.pfx.bak` can be
     * recovered, a truncated `.pfx` cannot be recovered at all.
     *
     * Until now "can be recovered" meant a human with a file manager, on a file with a random name, on
     * a phone. This is what makes the next login do it: `canOpenKeystore` is the first thing that opens
     * the store, so it is where the backup gets noticed while both candidate passwords are still in
     * play, and everything downstream then runs exactly as it would have.
     *
     * The aftermath is constructed rather than provoked, for the reason [stageChangeTo] gives about
     * interrupted password changes: there is no way to stop a thread between the two `Files.move` calls
     * that does not also skip the cleanup the crash is supposed to skip. What is built is precisely
     * what the code leaves — a byte copy of the live store at the backup path, and a truncated store —
     * and the recovery under test is entirely real.
     */
    @Test
    fun `login recovers from a stranded commit backup and still lands on a low-PBE store`() = runBlocking<Unit> {
        val derived = alreadyMigratedWithLegacyParameters()
        val keyBefore = identityKeyMaterial(derived)
        strandCommitBackupOverTruncatedStore()
        // Asserted with a passive read, not with `canOpenStore`: that helper goes through
        // `canOpenKeystore`, which is where the recovery now lives, so asking it here would perform
        // the very repair the test is about and then report the state afterwards.
        assertNull(
            keystoreClient.getKeyStoreInfo(Keystore(accountDirectory().absolutePath, "$user.pfx", derived)).getOrNull(),
            "precondition: the store as it sits on disk is unusable",
        )

        assertIs<Outcome.Success<AppUser>>(repository().login(user, loginPassword))

        assertTrue(canOpenStore(derived), "the login must put the backup back")
        assertContentEquals(
            keyBefore,
            identityKeyMaterial(derived),
            "and it must be the SAME RSA identity — recovery, not a fresh account",
        )
        assertLowPbeParameters(identityStoreFile().readBytes())
        assertFalse(identityStoreBackupFile().exists(), "a consumed backup must not linger in the sync directory")
    }

    /**
     * **The recovery must not fire when the store is fine.**
     *
     * `resolveIdentityStorePassword` asks `canOpenKeystore` with the derived password and then with the
     * login password, so a `false` answer is completely routine — it is how the migration state machine
     * works. If "this password did not open it" were the trigger for a restore, then a stale backup
     * from an older password would be published straight over a healthy current store, and the account
     * would lose the identity it was using in order to recover one it had abandoned. The trigger is
     * that the live store is not a readable PKCS#12 at all, which no password is needed to decide.
     */
    @Test
    fun `a stale backup from an old password is not restored over a store that opens`() = runBlocking<Unit> {
        assertIs<Outcome.Success<AppUser>>(signup(repository()))
        val derived = derivedStorePassword(loginPassword)
        val live = identityStoreFile().readBytes()
        val keyBefore = identityKeyMaterial(derived)
        // A complete, openable store sealed under a password this account has long since left.
        identityStoreBackupFile().writeBytes(storeSealedWithAnotherPassword())

        val repository = repository()
        repository.logout()
        assertIs<Outcome.Success<AppUser>>(repository.login(user, loginPassword))

        assertContentEquals(live, identityStoreFile().readBytes(), "the live store must not be touched")
        assertContentEquals(keyBefore, identityKeyMaterial(derived), "and the account keeps its own identity")
        assertTrue(identityStoreBackupFile().exists(), "a backup that was never consumed must not be deleted either")
    }

    /**
     * A backup that opens with neither password is not a recovery. It is left exactly where it is —
     * deleting it would destroy the only remaining evidence — and the login fails honestly instead of
     * publishing something it cannot vouch for.
     */
    @Test
    fun `a backup that opens with no known password is neither restored nor deleted`() = runBlocking<Unit> {
        alreadyMigratedWithLegacyParameters()
        val foreign = storeSealedWithAnotherPassword()
        strandCommitBackupOverTruncatedStore()
        identityStoreBackupFile().writeBytes(foreign)
        val truncated = identityStoreFile().readBytes()

        assertIs<Outcome.Error>(repository().login(user, loginPassword))

        assertContentEquals(foreign, identityStoreBackupFile().readBytes(), "the unverifiable backup stays put")
        assertContentEquals(truncated, identityStoreFile().readBytes(), "and nothing is published over the live store")
    }

    /**
     * The recovery must not open a new way to mint a master key over restorable state.
     *
     * `openOrCreateKeyring` refuses to mint when an identity store exists that the login password does
     * not open, because minting there would install a key the `.pfx` never accepts, over the one spot a
     * restore has to go. A truncated store whose backup belongs to a *lost* keyring is exactly that
     * situation wearing a disguise: the store looks damaged, but the thing that would fix it is a
     * keyring, not a new one. The restore refuses (the backup does not verify under the login
     * password), the guard still sees an unopenable store, and the login fails rather than minting.
     */
    @Test
    fun `a truncated store whose backup belongs to a lost keyring still refuses to mint`() = runBlocking<Unit> {
        val derived = alreadyMigratedWithLegacyParameters()
        strandCommitBackupOverTruncatedStore()
        val backup = identityStoreBackupFile().readBytes()
        // The keyring is gone — a restore of `database/` without `keystore/`, say. The backup is on the
        // derived password, which nothing can reproduce now.
        assertTrue(keyringFile().delete())

        assertIs<Outcome.Error>(repository().login(user, loginPassword))

        assertFalse(keyringFile().exists(), "minting here would strand the store under a key it never accepts")
        assertContentEquals(backup, identityStoreBackupFile().readBytes(), "and the recoverable copy is untouched")
        // The account is still recoverable by restoring the keyring, which is the whole point.
        assertTrue(derived.isNotEmpty())
    }

    // ----------------------------------------------------------------- setup

    /**
     * Signup as the app performs it: `SignUpUser` upserts the returned credential into preferences,
     * and without that a following login has nothing to verify against.
     */
    private suspend fun signup(repository: LocalUserRepository): Outcome<AppUser> =
        repository.signup(user, loginPassword, ringPassphrase).also { if (it is Outcome.Success) prefs.upsert(it.value) }

    /**
     * An account created the way the pre-keyring build created one: a `.pfx` sealed with the login
     * password, a stored credential, a vault, and no keyring anywhere.
     *
     * Written through `createKeyStore` + `addKeystoreKey` — the JCA path — rather than through
     * [JvmKeystoreLifecycle.createKeystoreForUser], because that is what wrote these files and
     * because it is what gives them the expensive PKCS#12 parameters the migration has to deal with.
     * Going through the lifecycle would produce a store that is already in the shape the tests below
     * are trying to reach.
     */
    private suspend fun legacyAccount() {
        val descriptor = keystoreClient.createKeyStore(
            keystoreType = KeyStoreType.PKCS12,
            keystorePath = accountDirectory().absolutePath,
            keystoreName = "$user.pfx",
            keystorePassword = loginPassword,
        ).getOrThrow()
        check(
            keystoreClient.addKeystoreKey(descriptor, IDENTITY_ALIAS, loginPassword, KeystoreKeyAlgorithm.RSA).getOrThrow(),
        ) { "could not write the legacy account's identity key" }
        storage.create(user, "legacy-vault-bytes".encodeToByteArray())
        prefs.credentials[user] = credentialFor(loginPassword)
        prefs.user = AppUser.LoggedIn(user, prefs.credentials.getValue(user))
    }

    private fun repository(
        keystoreLifecycle: KeystoreLifecycle = JvmKeystoreLifecycle(keystoreClient),
        vaultCipher: VaultCipher = this.vaultCipher,
        keyringRepository: KeyringRepository = KeyringStore(platform),
        userPreferences: UserPreferences = prefs,
    ) = LocalUserRepository(
        platform = platform,
        coroutinesContextFacade = UnconfinedFacade,
        userPreferences = userPreferences,
        keystoreLifecycle = keystoreLifecycle,
        pgpKeyRingService = pgp,
        storage = storage,
        passwordHasher = hasher,
        secureRandom = JvmSecureRandomService(),
        bioAuthService = AlwaysAllowBioAuth,
        keyringRepository = keyringRepository,
        vaultCipher = vaultCipher,
    )

    private fun credentialFor(password: String): Password {
        val salt = ByteArray(48) { it.toByte() }
        return Password(
            hash = Base64.Mime.encode(hasher.derive(password, salt, KdfParams.ARGON2ID_DEFAULT)),
            salt = Base64.Mime.encode(salt),
            kdf = KdfParams.ARGON2ID_DEFAULT, // already current, so no rehash-on-login fires
        )
    }

    private fun accountDirectory() = File(root, "keystore/$user")
    private fun keyringFile() = File(accountDirectory(), DirectoryBundler.KEYRING_FILE_NAME)
    private fun stagedKeyringFile() = File(accountDirectory(), DirectoryBundler.KEYRING_STAGED_FILE_NAME)
    private fun identityStoreFile() = File(accountDirectory(), "$user.pfx")

    /** The commit's recovery copy, under the one fixed name the sync exclusion can match. */
    private fun identityStoreBackupFile() =
        File(accountDirectory(), KeystoreClient.identityStoreBackupName("$user.pfx"))

    /**
     * The on-disk state a dual commit failure leaves: the backup is a byte copy of the live store,
     * which is all the commit's `copyDurably` writes, and the live store is truncated the way a
     * cross-device replace that got part way through a copy leaves it.
     */
    private fun strandCommitBackupOverTruncatedStore() {
        identityStoreBackupFile().writeBytes(identityStoreFile().readBytes())
        RandomAccessFile(identityStoreFile(), "rw").use { it.setLength(it.length() / 3) }
    }

    /**
     * A complete, openable identity store belonging to nothing this account can reach — built for
     * another username in a throwaway directory, so no password in play here opens it.
     */
    private suspend fun storeSealedWithAnotherPassword(): ByteArray {
        val other = Files.createTempDirectory("foreign-identity-store").toFile()
        try {
            val session = vaultCipher.createSession("an entirely unrelated password")
            try {
                JvmKeystoreLifecycle(keystoreClient)
                    .createKeystoreForUser("stranger", "${other.absolutePath}/", vaultCipher.identityStorePassword(session.sessionKey))
                    .getOrThrow()
            } finally {
                session.sessionKey.destroy()
            }
            return File(other, "stranger/stranger.pfx").readBytes()
        } finally {
            other.deleteRecursively()
        }
    }

    /**
     * The on-disk state a password change leaves behind after step one: the same device master key,
     * rewrapped under [password], staged beside the live keyring.
     *
     * Built by hand rather than by interrupting a real `changeUserPassword`. A crash is a process
     * that stops mid-method, and there is no way to make a thread do that which does not also run
     * the cleanup the crash is supposed to skip — so the state is constructed and the *next login* is
     * what is actually under test, which is the part that has to work.
     */
    private fun stageChangeTo(password: String): ByteArray {
        val session = vaultCipher.unlockSession(keyringFile().readBytes(), loginPassword)
        val staged = try {
            vaultCipher.rewrapSession(session, password)
        } finally {
            session.destroy()
        }
        KeyringStore(platform).writeNext(user, staged)
        return staged
    }

    /**
     * The derived store password as a plain `String`.
     *
     * Unwrapped at this boundary on purpose. Its consumers here — [canOpenStore], [storeAliases],
     * [identityKeyMaterial] — mirror `KeystoreLifecycle.canOpenKeystore`, which deliberately keeps a
     * `String` because it has to be asked with the **login** password too. Threading
     * `IdentityStorePassword` into them would mean `.value` at every call and prove nothing: the type
     * fences the low-PBE *writes*, and every write path in these tests goes through the production
     * code, which holds the real derived token end to end.
     */
    private fun derivedStorePassword(password: String): String {
        val session = vaultCipher.unlockSession(keyringFile().readBytes(), password)
        try {
            return vaultCipher.identityStorePassword(session).value
        } finally {
            session.destroy()
        }
    }

    private suspend fun canOpenStore(password: String): Boolean =
        JvmKeystoreLifecycle(keystoreClient).canOpenKeystore(user, "${root.absolutePath}/keystore/", password)

    /**
     * The state a device that has already migrated is in: the `.pfx` is on the derived password, but
     * it was put there by a JCA writer, so it still carries six-figure parameters.
     *
     * The re-seal is done with BouncyCastle's own `KeyStore` deliberately. `loadPkcs12` picks SUN when
     * the platform has one and BouncyCastle when it does not — and **Android does not** — so this is
     * the file an Android device that migrated is holding: 3DES and 40-bit RC2 at 600,000 with a SHA-1
     * MAC at 1,200,000. (A desktop migration lands on the JDK's own 10,000 instead, which the sniff
     * deliberately leaves alone; there is nothing worth rewriting a private key over.)
     *
     * @return the derived store password the account is now on.
     */
    private suspend fun alreadyMigratedWithLegacyParameters(): String {
        legacyAccount()
        val created = vaultCipher.createSession(loginPassword)
        KeyringStore(platform).write(user, created.keyringBytes)
        val derived = vaultCipher.identityStorePassword(created.sessionKey).value
        created.sessionKey.destroy()

        val legacy = checkNotNull(
            keystoreClient.getKeyStoreInfo(Keystore(accountDirectory().absolutePath, "$user.pfx", loginPassword)).getOrThrow(),
        )
        val identityKey = checkNotNull(keystoreClient.unwrapKey(legacy, IDENTITY_ALIAS, loginPassword.toCharArray()))
        val chain = legacy.getCertificateChain(IDENTITY_ALIAS)
        KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME).apply {
            load(null, derived.toCharArray())
            setKeyEntry(IDENTITY_ALIAS, identityKey, derived.toCharArray(), chain)
        }.let { rekeyed ->
            identityStoreFile().outputStream().use { rekeyed.store(it, derived.toCharArray()) }
        }

        assertTrue(canOpenStore(derived), "fixture precondition: the store is on the derived password")
        assertTrue(
            LowPbePkcs12Writer.hasLegacyPbe(identityStoreFile().readBytes()),
            "fixture precondition: it still carries the JCA writer's parameters",
        )
        return derived
    }

    private fun storeAliases(password: String): Set<String> =
        checkNotNull(
            keystoreClient.getKeyStoreInfo(Keystore(accountDirectory().absolutePath, "$user.pfx", password)).getOrThrow(),
        ).aliases().toList().map(String::lowercase).toSet()

    /** The encoded RSA private key itself, so "same aliases" cannot pass for "same identity". */
    private fun identityKeyMaterial(password: String): ByteArray {
        val store = checkNotNull(
            keystoreClient.getKeyStoreInfo(Keystore(accountDirectory().absolutePath, "$user.pfx", password)).getOrThrow(),
        )
        return checkNotNull(keystoreClient.unwrapKey(store, IDENTITY_ALIAS, password.toCharArray())).encoded
    }

    /**
     * Assert the PKCS#12 parameters directly out of the file's ASN.1 — no PBE, no password.
     *
     * `hasLegacyPbe` returning false is not the same assertion: it is also false for a store at the
     * JDK's own 10,000, which is a perfectly ordinary file that this change is not supposed to
     * produce. Reading the counts is what pins the writer that actually ran.
     */
    private fun assertLowPbeParameters(pfxBytes: ByteArray) {
        val pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(pfxBytes))
        val authenticatedSafe = AuthenticatedSafe.getInstance(
            ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(pfx.authSafe.content).octets),
        )

        val keyBagAlgorithms = authenticatedSafe.contentInfo
            .filter { it.contentType == PKCSObjectIdentifiers.data }
            .flatMap { contentInfo ->
                val bags = ASN1Sequence.getInstance(ASN1OctetString.getInstance(contentInfo.content).octets)
                (0 until bags.size()).map { SafeBag.getInstance(bags.getObjectAt(it)) }
            }
            .filter { it.bagId == PKCSObjectIdentifiers.pkcs8ShroudedKeyBag }
            .map { EncryptedPrivateKeyInfo.getInstance(it.bagValue).encryptionAlgorithm }
        assertTrue(keyBagAlgorithms.isNotEmpty(), "the store must hold a shrouded private key bag")
        val certificateAlgorithms = authenticatedSafe.contentInfo
            .filter { it.contentType == PKCSObjectIdentifiers.encryptedData }
            .map { EncryptedData.getInstance(it.content).encryptionAlgorithm }
        assertTrue(certificateAlgorithms.isNotEmpty(), "the store must hold an encrypted certificate section")

        (keyBagAlgorithms + certificateAlgorithms).forEach { algorithm ->
            assertEquals(PKCSObjectIdentifiers.id_PBES2, algorithm.algorithm, "every bag must be PBES2")
            val parameters = PBES2Parameters.getInstance(algorithm.parameters)
            assertEquals(PKCSObjectIdentifiers.id_PBKDF2, parameters.keyDerivationFunc.algorithm)
            val pbkdf2 = PBKDF2Params.getInstance(parameters.keyDerivationFunc.parameters)
            assertEquals(LowPbePkcs12Writer.ITERATIONS, pbkdf2.iterationCount.intValueExact())
            assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, pbkdf2.prf.algorithm)
            assertEquals(NISTObjectIdentifiers.id_aes256_CBC, parameters.encryptionScheme.algorithm)
        }

        val mac = assertNotNull(pfx.macData, "the store must carry a MAC")
        assertEquals(LowPbePkcs12Writer.ITERATIONS, mac.iterationCount.intValueExact())
        assertEquals(NISTObjectIdentifiers.id_sha256, mac.mac.algorithmId.algorithm)
    }

    private suspend fun sessionScope() = KoinPlatform.getKoin()
        .getOrCreateScope("session-${prefs.getSessionId()}", named("sessionScope"))

    private suspend fun vaultSession(): VaultSession = sessionScope().get(named(VAULT_SESSION_HANDLE))

    private object AuthFailureNames {
        const val ACCOUNT_ALREADY_EXISTS = "AccountAlreadyExists"
        const val INVALID_PASSWORD = "InvalidPassword"
    }

    /** Where a concurrent login is held so the other one can overtake it. */
    private enum class ParkPoint { READ, CREATE_NEW }

    // ----------------------------------------------------------------- fakes

    /**
     * Real storage, with one call held open so a second login can overtake the first.
     *
     * Deliberately a decorator on the production [KeyringStore] rather than a fake: the thing under
     * test is the interaction between the repository's ordering and the store's `O_EXCL` claim, and
     * a fake store would prove only that the fake agrees with itself. Only the *first* caller parks,
     * so the winner runs through untouched.
     */
    private class ParkingKeyringRepository(
        private val delegate: KeyringRepository,
        private val parkOn: ParkPoint,
        private val reached: CountDownLatch,
        private val release: CountDownLatch,
    ) : KeyringRepository by delegate {
        private val armed = AtomicBoolean(true)

        override fun read(username: String): ByteArray? {
            // Answer first, then park: the point is to resume holding a *stale* answer.
            val answer = delegate.read(username)
            if (parkOn == ParkPoint.READ) park()
            return answer
        }

        override fun createNew(username: String, bytes: ByteArray): Boolean {
            if (parkOn == ParkPoint.CREATE_NEW) park()
            return delegate.createNew(username, bytes)
        }

        private fun park() {
            if (!armed.compareAndSet(true, false)) return
            reached.countDown()
            check(release.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "the parked login was never released" }
        }
    }

    /**
     * Deterministic and cheap. The *credential* KDF is not what these tests are about and running it
     * for real would add a 64 MiB Argon2id to every login here; the keyring's Argon2id is real,
     * because it is the one the design depends on.
     */
    private class CountingPasswordHasher : PasswordHasher {
        var deriveCount = 0
            private set

        override fun derive(password: String, salt: ByteArray, params: KdfParams): ByteArray {
            deriveCount++
            return MessageDigest.getInstance("SHA-256").apply {
                update(password.encodeToByteArray())
                update(salt)
                update(params.algorithm.encodeToByteArray())
            }.digest()
        }

        fun reset() {
            deriveCount = 0
        }
    }

    /** Counts keyring operations without changing any of their behaviour. */
    private class CountingVaultCipher(private val delegate: VaultCipher) : VaultCipher by delegate {
        var unlockCount = 0
            private set
        var createCount = 0
            private set

        override fun unlockSession(keyringBytes: ByteArray, password: String): VaultSessionKey {
            unlockCount++
            return delegate.unlockSession(keyringBytes, password)
        }

        override fun createSession(password: String) = delegate.createSession(password).also { createCount++ }
    }

    /** Real behaviour, except that the two store rewrites can be made to fail on demand. */
    private class FlakyKeystoreLifecycle(private val delegate: KeystoreLifecycle) : KeystoreLifecycle by delegate {
        var failChangePassword = false
        var failReencode = false

        override suspend fun changeKeystorePassword(
            username: String,
            keystoreDir: String,
            oldPassword: String,
            newPassword: IdentityStorePassword,
        ): Outcome<Unit> = if (failChangePassword) {
            Outcome.Error("simulated failure", ai.passman.domain.keystore.exception.KeystoreFailure.ChangePasswordFailure)
        } else {
            delegate.changeKeystorePassword(username, keystoreDir, oldPassword, newPassword)
        }

        override suspend fun reencodeIdentityStoreIfLegacy(
            username: String,
            keystoreDir: String,
            password: IdentityStorePassword,
        ): Outcome<Unit> = if (failReencode) {
            Outcome.Error("simulated failure", ai.passman.domain.keystore.exception.KeystoreFailure.ChangePasswordFailure)
        } else {
            delegate.reencodeIdentityStoreIfLegacy(username, keystoreDir, password)
        }
    }

    private class FakePgpKeyRingService : PgpKeyRingService {
        var failing = false

        /** Every (userId, passphrase) handed to the ring service — what the decoupling tests read. */
        val createCalls = mutableListOf<Pair<String, String>>()

        override suspend fun createKeyRings(userId: String, password: String, keyDirectory: String): Result<Unit> {
            createCalls += userId to password
            return if (failing) Result.failure(IllegalStateException("simulated pgp failure")) else Result.success(Unit)
        }
    }

    private class FakeStorage : PasswordDatabaseStorage {
        private val vaults = mutableMapOf<String, ByteArray>()
        private val preMigration = mutableMapOf<String, ByteArray>()
        /** The restore drill: the database directory comes back empty while `keystore/` survives. */
        override fun delete(username: String) {
            vaults.remove(username)
        }
        override fun exists(username: String): Boolean = username in vaults
        override fun create(username: String, initialEncryptedBytes: ByteArray) {
            vaults[username] = initialEncryptedBytes
        }
        override fun read(username: String): ByteArray = vaults.getValue(username)
        override fun write(username: String, encryptedBytes: ByteArray) {
            vaults[username] = encryptedBytes
        }
        override fun retainPreMigration(username: String, ciphertext: ByteArray): Boolean =
            preMigration.putIfAbsent(username, ciphertext) == null
        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean {
            if (!vaults[username].contentEquals(expected)) return false
            vaults[username] = replacement
            return true
        }
    }

    private class FakePreferences : UserPreferences {
        val credentials = mutableMapOf<String, Password>()
        var user: AppUser = AppUser.Anonymous

        /** Lets a test fail one specific credential write — the rollback's, and only the rollback's. */
        var failUpsertWhen: (AppUser) -> Boolean = { false }

        override suspend fun getUser(): AppUser = user
        override suspend fun upsert(user: AppUser) {
            if (failUpsertWhen(user)) throw java.io.IOException("simulated credential write failure")
            this.user = user
            if (user is AppUser.LoggedIn) credentials[user.userName] = user.password
        }
        override suspend fun getStoredCredentials(username: String): Password? = credentials[username]
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "keyring-bootstrap-test"
        override suspend fun clear() = Unit
    }

    private object AlwaysAllowBioAuth : BioAuthService {
        override suspend fun authenticate(hardwareKeySeed: ByteArray?): BioAuthService.Result =
            BioAuthService.Result.Success
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }
}
