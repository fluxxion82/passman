package ai.passman.platform.recovery

import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.keyring.KeyFileEnvelope
import ai.passman.crypto.keyring.KeyFilePurpose
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.domain.settings.model.PortableVaultRecoveryFormat
import ai.passman.keystore.LowPbePkcs12Writer
import ai.passman.keystore.Pkcs12Certificates
import ai.passman.platform.crypto.JvmSecureRandomService
import ai.passman.repo.Platform
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JvmPortableVaultRecoveryTest {

    private val root = Files.createTempDirectory("portable-recovery-test").toFile()

    @AfterTest
    fun tearDown() {
        root.deleteRecursively()
    }

    /**
     * Creating the recovery material holds `keystore/<user>/`'s artifact-directory lock.
     *
     * Two of the four filenames this class writes are **user-derived** — `<user>.recovery.p12` and
     * `<user>.recovery.crt` — and the sync exclusion list that is supposed to keep them off the wire
     * is a basename string comparison, so a username carrying path syntax or a decomposable character
     * makes them displaceable exactly as `IdentityStoreExclusionTest` shows for `<user>.pfx`. The
     * P12 is this device's recovery private key; a peer's copy landing over a freshly written one
     * leaves it unopenable by the local record, and that surfaces only when the user finally needs
     * their recovery phrase.
     *
     * Observed by probing the OS lock while the call runs rather than by timing it: RSA generation
     * and two PKCS#12 writes take far longer than any "did it block" threshold would mean anything
     * against.
     */
    @Test
    fun access_holdsTheArtifactDirectoryLockWhileItWrites() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val recovery = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService())
            val accountDir = File(root, "keystore/work")
            val lockFile = File(accountDir.parentFile, "${accountDir.name}.lock")

            val running = java.util.concurrent.atomic.AtomicBoolean(true)
            var observed = false
            val worker = kotlin.concurrent.thread {
                try {
                    runCatching { recovery.access("work", session) }
                } finally {
                    running.set(false)
                }
            }
            while (running.get() && !observed) {
                observed = lockIsHeld(lockFile)
                Thread.onSpinWait()
            }
            worker.join(java.util.concurrent.TimeUnit.SECONDS.toMillis(120))

            assertTrue(observed, "the recovery writer must hold the artifact-directory lock while it writes")
        } finally {
            session.destroy()
        }
    }

    /**
     * For a username carrying a separator, the writes lock the **account directory** — so no lock
     * file lands inside the tree sync bundles.
     *
     * Usernames are gated on trimmed length alone, so `team/a` is a legal account. Every recovery
     * path is then built by concatenation: `p12File("team/a")` is
     * `keystore/team/a/team/a.recovery.p12`, whose own parent is `keystore/team/a/team` — while sync
     * locks `keystore/team/a`. Keying a write on the target's parent therefore took a different lock
     * from the one it had to agree with, which is no exclusion at all.
     *
     * Asserted through the consequence rather than the key, because the consequence is worse than the
     * missing exclusion: that wrong lock file is created *inside* the account directory, and
     * `DirectoryBundler.bundle` walks every descendant of it. The stray lock would have been packed
     * into the next outbound bundle and shipped to every paired peer. A sibling, which is what the
     * corrected key produces, is outside that walk by construction.
     */
    @Test
    fun access_forAUsernameWithASeparator_keepsItsLockFileOutOfTheBundledTree() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val recovery = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService())

            recovery.access("team/a", session)

            val accountDir = File(root, "keystore/team/a")
            assertTrue(accountDir.isDirectory, "precondition: the account directory is the nested one")
            val strays = accountDir.walkTopDown().filter { it.name.endsWith(".lock") }.toList()
            assertTrue(
                strays.isEmpty(),
                "no lock file may sit inside the directory bundle() walks; found $strays",
            )
        } finally {
            session.destroy()
        }
    }

    /**
     * Two callers racing the very first access both succeed, and agree.
     *
     * The choice between opening an existing record and creating one was made *outside* the lock, so
     * both callers took the create branch: the first completed the set, the second then hit
     * `check(!p12File.exists() && !certificateFile.exists())` and threw — because a half-present set
     * is indistinguishable from a half-destroyed one, which is exactly the check that must stay. The
     * fix was to lock the dispatch, not to weaken the check: the loser now waits, finds the record,
     * and opens it.
     *
     * Reachable on an ordinary login, where more than one caller can want recovery material at once.
     */
    @Test
    fun access_racingTheFirstCreationYieldsOneAgreedSetOfMaterial() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val recovery = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService())
            val go = java.util.concurrent.CountDownLatch(1)
            val results = java.util.Collections.synchronizedList(mutableListOf<Result<String>>())

            val racers = (1..2).map {
                kotlin.concurrent.thread {
                    go.await()
                    results += runCatching { recovery.access("racer", session).recoveryPassword }
                }
            }
            go.countDown()
            racers.forEach { it.join(java.util.concurrent.TimeUnit.SECONDS.toMillis(120)) }

            assertEquals(2, results.size, "both callers must return")
            results.forEach { assertTrue(it.isSuccess, "neither caller may fail: ${it.exceptionOrNull()}") }
            assertEquals(
                results[0].getOrThrow(),
                results[1].getOrThrow(),
                "and both must see the same recovery material, not two different creations",
            )
        } finally {
            session.destroy()
        }
    }

    /** True when some code in this JVM currently holds the OS lock on [lockFile]. */
    private fun lockIsHeld(lockFile: File): Boolean {
        if (!lockFile.isFile) return false
        return try {
            java.nio.channels.FileChannel.open(
                lockFile.toPath(),
                java.nio.file.StandardOpenOption.WRITE,
            ).use { channel ->
                val lock = channel.tryLock()
                if (lock == null) true else { lock.release(); false }
            }
        } catch (_: java.nio.channels.OverlappingFileLockException) {
            true
        } catch (_: java.io.IOException) {
            false
        }
    }

    @Test
    fun ensure_createsAStableSealedRecoveryP12ForTheProfile() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val recovery = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService())

            val first = recovery.access("work", session)
            val second = recovery.access("work", session)

            assertEquals(first, second)
            assertEquals(PortableVaultRecoveryFormat.Bip39English24, first.recoveryFormat)
            assertEquals(24, first.recoveryPassword.split(' ').size)
            assertTrue(Bip39RecoveryPhrase.isValid(first.recoveryPassword))
            assertTrue(File(first.pkcs12Path).isFile)
            assertTrue(File(first.certificatePath).isFile)
            assertTrue(File(root, "keystore/work/portable-recovery.pmk").isFile)
            assertEquals(
                File(root, "database/${"work".hashCode()}_encrypted_passman.database").absolutePath,
                first.vaultPath,
            )
        } finally {
            session.destroy()
        }
    }

    @Test
    fun opens_existing_versionOneBase64UrlRecoveryRecord() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val fixture = createLegacyFixture("legacy", session)

            val access = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService()).access(fixture.username, session)

            assertEquals(PortableVaultRecoveryFormat.LegacyBase64Url, access.recoveryFormat)
            assertEquals(fixture.password, access.recoveryPassword)
        } finally {
            session.destroy()
        }
    }

    @Test
    fun explicitly_upgradesLegacyRecoveryP12WithoutChangingItsKeyCertificateOrVault() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val fixture = createLegacyFixture("legacy", session)
            val vault = File(root, "database/${fixture.username.hashCode()}_encrypted_passman.database")
            val originalVault = byteArrayOf(1, 2, 3, 4)
            vault.parentFile!!.mkdirs()
            vault.writeBytes(originalVault)
            val recovery = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService())

            val upgraded = recovery.upgrade(fixture.username, session)

            assertEquals(PortableVaultRecoveryFormat.Bip39English24, upgraded.recoveryFormat)
            assertTrue(Bip39RecoveryPhrase.isValid(upgraded.recoveryPassword))
            assertContentEquals(
                fixture.certificate.encoded,
                (openP12(File(upgraded.pkcs12Path), upgraded.recoveryPassword).getCertificate("passmanRecovery") as X509Certificate).encoded,
            )
            assertFailsWith<Exception> { openP12(File(upgraded.pkcs12Path), fixture.password) }
            assertContentEquals(originalVault, vault.readBytes())
            assertFalse(File(root, "keystore/${fixture.username}/portable-recovery.previous").exists())
        } finally {
            session.destroy()
        }
    }

    @Test
    fun restoresLegacyP12AfterAnInterruptedUpgradeBeforeOpeningIt() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val fixture = createLegacyFixture("interrupted", session)
            val profile = File(root, "keystore/${fixture.username}")
            val phrase = Bip39RecoveryPhrase.fromEntropy(ByteArray(32) { 1 })
            File(profile, "portable-recovery.previous").writeBytes(fixture.p12)
            File(profile, "${fixture.username}.recovery.p12").writeBytes(
                LowPbePkcs12Writer.encode(
                    "passmanRecovery",
                    fixture.keyPair.private,
                    listOf(fixture.certificate),
                    phrase.toCharArray(),
                ),
            )

            val access = JvmPortableVaultRecovery(platform(root), JvmSecureRandomService()).access(fixture.username, session)

            assertEquals(PortableVaultRecoveryFormat.LegacyBase64Url, access.recoveryFormat)
            assertContentEquals(fixture.p12, File(access.pkcs12Path).readBytes())
            assertFalse(File(profile, "portable-recovery.previous").exists())
        } finally {
            session.destroy()
        }
    }

    /**
     * A record sealed under another device's master key — exactly what a keystore sync from before
     * the recovery-file exclusions left behind. The failure must stay a failure (fail closed; no
     * self-heal), but it must name the cause and the files involved rather than surfacing as a bare
     * authentication error, because "the RECOVERY_PASSWORD key file failed authentication" points an
     * operator at nothing.
     */
    @Test
    fun open_namesTheRecoveryArtifactsWhenAForeignSealedRecordDoesNotOpen() {
        val peerSession = PasswordVaultCipher().createSession("peer-login").sessionKey
        val localSession = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            createLegacyFixture("synced", peerSession)

            val failure = assertFailsWith<IllegalStateException> {
                JvmPortableVaultRecovery(platform(root), JvmSecureRandomService()).access("synced", localSession)
            }

            val message = failure.message.orEmpty()
            assertTrue("portable-recovery.pmk" in message, "must name the sealed record, was: $message")
            assertTrue("synced.recovery.p12" in message, "must name the recovery P12, was: $message")
            assertTrue("synced.recovery.crt" in message, "must name the certificate, was: $message")
        } finally {
            peerSession.destroy()
            localSession.destroy()
        }
    }

    private fun createLegacyFixture(username: String, session: VaultSessionKey): LegacyFixture {
        val password = "K5M75bFE9Vqapxvt_KiOv0_9k7tKEtQJ1-aNSkN0KpQ"
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val certificate = Pkcs12Certificates.selfSignedRsa(keyPair, "Passman portable recovery $username")
        val profile = File(root, "keystore/$username").apply { mkdirs() }
        val p12 = LowPbePkcs12Writer.encode("passmanRecovery", keyPair.private, listOf(certificate), password.toCharArray())
        File(profile, "$username.recovery.p12").writeBytes(p12)
        val pin = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        val passwordBytes = password.encodeToByteArray()
        val record = byteArrayOf(1, passwordBytes.size.toByte()) + passwordBytes + pin
        val sealed = KeyFileEnvelope.seal(record, KeyFilePurpose.RECOVERY_PASSWORD, session)
        File(profile, "portable-recovery.pmk").writeBytes(sealed)
        return LegacyFixture(username, password, keyPair, certificate, p12)
    }

    private fun openP12(file: File, password: String): KeyStore {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        return KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME).apply {
            file.inputStream().use { load(it, password.toCharArray()) }
        }
    }

    private data class LegacyFixture(
        val username: String,
        val password: String,
        val keyPair: KeyPair,
        val certificate: X509Certificate,
        val p12: ByteArray,
    )

    private fun platform(root: File) = object : Platform() {
        override fun getLocalPath(): String = root.absolutePath
    }
}
