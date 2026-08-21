package ai.passman.repo.repositories

import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.keys.model.EDDSA
import ai.passman.pgp.bundled.BundledDeveloperKey
import ai.passman.pgp.service.PgpClient
import ai.passman.pgp.utils.PgpKeys
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.platform.transfer.PgpTransferService
import ai.passman.repo.Platform
import ai.passman.domain.base.DefaultContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.repository.PgpPreferences
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

class LocalPgpRepositoryTest {
    private lateinit var localDir: File
    private lateinit var pgpUserDir: File
    private lateinit var repository: LocalPgpRepository
    private lateinit var pgpPreferences: FakePgpPreferences
    private lateinit var publicRing: PGPPublicKeyRing
    private lateinit var secretRing: PGPSecretKeyRing

    private val developerKeyFile get() = File(pgpUserDir, BundledDeveloperKey.FILE_NAME)

    private val secretRingFile get() = File(pgpUserDir, "key_secret_ring.asc")
    private val publicRingFile get() = File(pgpUserDir, "key_public_ring.asc")

    private class FakePlatform(private val localPath: File) : Platform() {
        override fun getLocalPath(): String = localPath.absolutePath
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("password", "salt"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "pgp-repository-test"
        override suspend fun clear() = Unit
    }

    private class FakePgpPreferences : PgpPreferences {
        val developerKeyImportedFor = mutableSetOf<String>()
        override suspend fun getPgpKeyList(): List<PgpKey> = emptyList()
        override suspend fun addPgpKey(pgpKey: PgpKey) = Unit
        override suspend fun addPgpKeys(pgpKeys: List<PgpKey>) = Unit
        override suspend fun isDeveloperKeyImported(userName: String): Boolean =
            userName in developerKeyImportedFor
        override suspend fun setDeveloperKeyImported(userName: String) {
            developerKeyImportedFor += userName
        }
    }

    private class FakeTransferService : PgpTransferService {
        override suspend fun transferPgpBundle(
            decryptedBundleBytes: ByteArray,
            fileName: String,
            device: TrustedDevice,
            port: Int,
        ): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun pullPgpBundle(device: TrustedDevice, port: Int): Outcome<ByteArray> =
            Outcome.Success(ByteArray(0))
    }

    @BeforeTest
    fun setUp() {
        localDir = Files.createTempDirectory("local-pgp-repository-test").toFile()
        pgpUserDir = File(localDir, "pgp/alice").apply { mkdirs() }

        // Real ring files, named the way createPgpKey names them. Sorted by name the public
        // ring is read BEFORE the secret ring ('p' < 's'), so a last-file-wins dedup would let
        // the secret ring's synthesized public entry take over the listed public path.
        val generator = PgpKeys.createPgpKeyRingGenerator(
            userId = "Test User <test@example.com>",
            algorithm = EDDSA,
            length = 256,
            expirationInSeconds = 0,
            password = "test-password",
        )
        secretRing = generator.generateSecretKeyRing()
        publicRing = generator.generatePublicKeyRing()
        PgpKeys.saveSecretKeyRingToFile(secretRing, secretRingFile.absolutePath)
        PgpKeys.savePublicKeyRingToFile(publicRing, publicRingFile.absolutePath)

        pgpPreferences = FakePgpPreferences()
        repository = LocalPgpRepository(
            platform = FakePlatform(localDir),
            coroutinesContextFacade = DefaultContextFacade(),
            pgpClient = PgpClient(),
            userPreferences = FakePreferences(),
            pgpTransferService = FakeTransferService(),
            pgpPreferences = pgpPreferences,
        )
    }

    @AfterTest
    fun tearDown() {
        localDir.deleteRecursively()
    }

    @Test
    fun getKeys_publicEntryPathAlwaysPointsAtThePublicRingFile() = runBlocking {
        val pair = repository.getKeys().single()

        assertEquals(PgpKeyType.Public, pair.publicKey.type)
        assertEquals(publicRingFile.absolutePath, pair.publicKey.path)
        assertEquals(secretRingFile.absolutePath, requireNotNull(pair.secretKey).path)
    }

    @Test
    fun getKeys_skipsFilesThatDoNotParseAsKeyRings() = runBlocking {
        // Sorts before both ring files, so it is processed first.
        File(pgpUserDir, "aaa_corrupt.asc").writeText(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot base64 at all!!!\n-----END PGP PUBLIC KEY BLOCK-----\n",
        )

        val pairs = repository.getKeys()

        assertEquals(publicRingFile.absolutePath, pairs.single().publicKey.path)
    }

    @Test
    fun importPgpFile_refusesAFileThatIsNotAKeyRingInsteadOfCopyingIt() = runBlocking {
        val notAKey = File(localDir, "holiday.png").apply { writeBytes(ByteArray(64) { it.toByte() }) }

        val outcome = repository.importPgpFile(notAKey.absolutePath)

        assertEquals(PgpFailure.ImportKeyFailure, assertIs<Outcome.Error>(outcome).cause)
        // The old implementation was a bare Files.copy, so this file used to land in the key
        // directory and report success.
        assertFalse(File(pgpUserDir, "holiday.png").exists())
    }

    @Test
    fun importPgpFile_refusesAKeyWhoseAlgorithmThisBuildCannotRead() = runBlocking {
        val future = File(localDir, "future_key.asc").apply {
            writeBytes(binaryRingWithUnknownSubkey())
        }

        val outcome = repository.importPgpFile(future.absolutePath)

        val cause = assertIs<PgpFailure.UnsupportedKeyAlgorithm>(assertIs<Outcome.Error>(outcome).cause)
        assertEquals(UNKNOWN_ALGORITHM_ID, cause.algorithmId)
        assertFalse(File(pgpUserDir, "future_key.asc").exists())
    }

    @Test
    fun importPgpFile_stillAcceptsARealKeyRing() = runBlocking {
        val exported = File(localDir, "friend_public.asc").apply { writeBytes(publicRingFile.readBytes()) }

        val outcome = repository.importPgpFile(exported.absolutePath)

        assertIs<Outcome.Success<Unit>>(outcome)
        assertTrue(File(pgpUserDir, "friend_public.asc").exists())
    }

    @Test
    fun getPublicKeyPath_refusesARingCarryingAnAlgorithmThisBuildCannotRead() = runBlocking {
        // Written straight into the key directory, the way a synced ring arrives: sync unbundles
        // raw bytes and never goes through import, so the import guard cannot have seen this file.
        val keyId = repository.getKeys().single().publicKey.keyId
        publicRingFile.writeBytes(binaryRingWithUnknownSubkey())

        val outcome = repository.getPublicKeyPath(keyId)

        val cause = assertIs<PgpFailure.UnsupportedKeyAlgorithm>(assertIs<Outcome.Error>(outcome).cause)
        assertEquals(UNKNOWN_ALGORITHM_ID, cause.algorithmId)
    }

    @Test
    fun getKeys_stillListsARingWithAnUnreadableAlgorithmSoItCanBeDeleted() = runBlocking {
        val before = repository.getKeys().single().publicKey.keyId
        publicRingFile.writeBytes(binaryRingWithUnknownSubkey())

        // Refusing to LIST it would leave the user no way to remove it — delete resolves the file
        // through the same listing. Sharing it is what gets refused, not seeing it.
        assertEquals(before, repository.getKeys().single().publicKey.keyId)
    }

    /**
     * The test ring, in binary, with one extra public-subkey packet using an algorithm id nobody
     * assigns today (35 is ML-KEM in the RFC 9580 registry). BouncyCastle drops that subkey
     * silently and reports the ring as whole, which is exactly the case the guard exists for.
     *
     * Binary rather than armored on purpose: bytes appended AFTER an armor block are invisible,
     * since the dearmorer stops at the tail line. A ring doctored that way would prove nothing.
     */
    private fun binaryRingWithUnknownSubkey(): ByteArray {
        val ring = PGPUtil.getDecoderStream(publicRingFile.inputStream()).use { it.readBytes() }
        return ring + unknownAlgorithmSubkeyPacket()
    }

    private fun unknownAlgorithmSubkeyPacket(): ByteArray {
        val body = mutableListOf<Byte>()
        body += 4 // version
        repeat(4) { body += 0x00 } // creation time
        body += UNKNOWN_ALGORITHM_ID.toByte()
        repeat(32) { body += 0x2A } // stand-in key material
        val header = (0x80 or (14 shl 2)).toByte() // old format, public subkey, one-byte length
        return byteArrayOf(header, body.size.toByte()) + body.toByteArray()
    }

    @Test
    fun getPublicKeyPath_returnsThePublicRingFilePath() = runBlocking {
        val keyId = repository.getKeys().single().publicKey.keyId

        val outcome = repository.getPublicKeyPath(keyId)

        assertEquals(publicRingFile.absolutePath, assertIs<Outcome.Success<String>>(outcome).value)
    }

    @Test
    fun getPublicKeyPath_failsWhenOnlyTheSecretRingExists() = runBlocking<Unit> {
        val keyId = repository.getKeys().single().publicKey.keyId
        check(publicRingFile.delete())

        // The listing keeps the pair visible (decrypt flows rely on it) with the only path
        // there is — the secret ring's...
        assertEquals(secretRingFile.absolutePath, repository.getKeys().single().publicKey.path)
        // ...but the share flow gets an error, never that path.
        assertIs<Outcome.Error>(repository.getPublicKeyPath(keyId))
    }

    @Test
    fun getPublicKeyPath_skipsCombinedFilesThatAlsoCarryASecretRing() = runBlocking {
        // A single imported file can hold both rings concatenated (the GnuPG keyring layout);
        // sharing it would leak the secret ring. Sorts first, so it is the naive first match.
        writeCombinedRingFile("aaa_combined.pgp")

        val keyId = repository.getKeys().single().publicKey.keyId
        val outcome = repository.getPublicKeyPath(keyId)

        assertEquals(publicRingFile.absolutePath, assertIs<Outcome.Success<String>>(outcome).value)
    }

    @Test
    fun getPublicKeyPath_failsWhenEveryPublicRingFileAlsoCarriesASecretRing() = runBlocking<Unit> {
        writeCombinedRingFile("aaa_combined.pgp")
        check(publicRingFile.delete())

        val keyId = repository.getKeys().single().publicKey.keyId

        assertIs<Outcome.Error>(repository.getPublicKeyPath(keyId))
    }

    @Test
    fun getKeys_and_getPublicKeyPath_pickTheSameFileWhenDuplicatePublicRingsExist() = runBlocking {
        // Same public ring under a second name: the listing and the share flow must agree on
        // which file represents the key, or details would show one file and export another.
        PgpKeys.savePublicKeyRingToFile(publicRing, File(pgpUserDir, "zzz_dup_public_ring.asc").absolutePath)

        val pair = repository.getKeys().single()
        val outcome = repository.getPublicKeyPath(pair.publicKey.keyId)

        assertEquals(publicRingFile.absolutePath, pair.publicKey.path)
        assertEquals(publicRingFile.absolutePath, assertIs<Outcome.Success<String>>(outcome).value)
    }

    @Test
    fun getSecretKeyPath_returnsTheSecretRingPathForTheCorrectPassphrase() = runBlocking {
        val keyId = repository.getKeys().single().publicKey.keyId

        val outcome = repository.getSecretKeyPath(keyId, "test-password")

        assertEquals(secretRingFile.absolutePath, assertIs<Outcome.Success<String>>(outcome).value)
    }

    @Test
    fun getSecretKeyPath_refusesAWrongPassphrase() = runBlocking<Unit> {
        val keyId = repository.getKeys().single().publicKey.keyId

        val outcome = repository.getSecretKeyPath(keyId, "not-the-password")

        assertEquals(PgpFailure.WrongPassword, assertIs<Outcome.Error>(outcome).cause)
    }

    @Test
    fun getSecretKeyPath_skipsAMultiKeySecretFileWhenTheStandaloneRingExists() = runBlocking {
        // Two keys' secret rings concatenated in one file; sorts first, so it is the naive
        // first match for the key.
        writeMultiKeySecretFile("aaa_multi_secret.pgp")

        val keyId = repository.getKeys().first { it.publicKey.path == publicRingFile.absolutePath }.publicKey.keyId
        val outcome = repository.getSecretKeyPath(keyId, "test-password")

        assertEquals(secretRingFile.absolutePath, assertIs<Outcome.Success<String>>(outcome).value)
    }

    @Test
    fun getSecretKeyPath_refusesWhenTheKeyOnlyLivesInAMultiKeySecretFile() = runBlocking<Unit> {
        writeMultiKeySecretFile("aaa_multi_secret.pgp")
        val keyId = repository.getKeys().first { it.publicKey.path == publicRingFile.absolutePath }.publicKey.keyId
        check(secretRingFile.delete())

        val outcome = repository.getSecretKeyPath(keyId, "test-password")

        // Exporting that file would leak the OTHER key's secret ring with it.
        assertEquals(PgpFailure.ExportPrivateKeyFailure, assertIs<Outcome.Error>(outcome).cause)
    }

    @Test
    fun getSecretKeyPath_refusesACombinedPublicAndSecretFile() = runBlocking<Unit> {
        writeCombinedRingFile("aaa_combined.pgp")
        val keyId = repository.getKeys().single().publicKey.keyId
        check(secretRingFile.delete())

        val outcome = repository.getSecretKeyPath(keyId, "test-password")

        assertEquals(PgpFailure.ExportPrivateKeyFailure, assertIs<Outcome.Error>(outcome).cause)
    }

    @Test
    fun getSecretKeyPath_refusesAnUnencryptedSecretRingUnderAnyPassphrase() = runBlocking<Unit> {
        // A ring whose keys carry no passphrase protection "unlocks" under ANY input — BC's
        // extract just passes the plaintext through. Accepting that would both fake the
        // verification and ship an unprotected secret ring.
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build("test-password".toCharArray())
        val unencrypted = PGPSecretKeyRing.copyWithNewPassword(secretRing, decryptor, null)
        check(secretRingFile.delete())
        PgpKeys.saveSecretKeyRingToFile(unencrypted, secretRingFile.absolutePath)
        val keyId = repository.getKeys().single().publicKey.keyId

        assertEquals(
            PgpFailure.ExportPrivateKeyFailure,
            assertIs<Outcome.Error>(repository.getSecretKeyPath(keyId, "test-password")).cause,
        )
        assertEquals(
            PgpFailure.ExportPrivateKeyFailure,
            assertIs<Outcome.Error>(repository.getSecretKeyPath(keyId, "anything at all")).cause,
        )
    }

    @Test
    fun getSecretKeyPath_refusesAGnuDummySecretKeyStub() = runBlocking<Unit> {
        // gpg --export-secret-subkeys writes the primary as a GNU-dummy stub; BC extracts it to
        // null WITHOUT throwing, so "no exception" must never count as a verified unlock.
        writeGnuDummySecretRing("aaa_dummy_secret.gpg")
        val keyId = repository.getKeys().single().publicKey.keyId
        check(secretRingFile.delete())

        val outcome = repository.getSecretKeyPath(keyId, "test-password")

        assertEquals(PgpFailure.ExportPrivateKeyFailure, assertIs<Outcome.Error>(outcome).cause)
    }

    @Test
    fun getSecretKeyPath_unlocksABinaryUnarmoredSecretRing() = runBlocking {
        // Imports copy files verbatim, so a secret ring can sit on disk in binary form.
        val keyId = repository.getKeys().single().publicKey.keyId
        check(secretRingFile.delete())
        val binaryFile = File(pgpUserDir, "key_secret_ring.gpg")
        binaryFile.outputStream().use { secretRing.encode(it) }

        val outcome = repository.getSecretKeyPath(keyId, "test-password")

        assertEquals(binaryFile.absolutePath, assertIs<Outcome.Success<String>>(outcome).value)
    }

    @Test
    fun keyListingIgnoresTempStagingFiles() = runBlocking {
        // VALID ring bytes under a temp-staging name that sorts FIRST: without the filter the
        // first-in-name-order dedup would list the staging file's path — a path about to vanish
        // on the atomic replace, or permanent debris after a crashed writer.
        val temp = File(pgpUserDir, "aaa_staged.3${DirectoryBundler.TEMP_FILE_SUFFIX}")
        PgpKeys.savePublicKeyRingToFile(publicRing, temp.absolutePath)

        val pair = repository.getKeys().single()

        assertEquals(publicRingFile.absolutePath, pair.publicKey.path)
        assertEquals(
            publicRingFile.absolutePath,
            assertIs<Outcome.Success<String>>(repository.getPublicKeyPath(pair.publicKey.keyId)).value,
        )
    }

    @Test
    fun getSecretKeyPath_neverResolvesToATempStagingFile() = runBlocking<Unit> {
        val keyId = repository.getKeys().single().publicKey.keyId
        val temp = File(pgpUserDir, "aaa_staged.7${DirectoryBundler.TEMP_FILE_SUFFIX}")
        PgpKeys.saveSecretKeyRingToFile(secretRing, temp.absolutePath)
        check(secretRingFile.delete())

        // The only file holding the secret ring is staging debris; exporting it would hand out
        // a path with no durability contract.
        assertIs<Outcome.Error>(repository.getSecretKeyPath(keyId, "test-password"))
    }

    @Test
    fun deletePgpKey_leavesTempStagingFilesAlone() = runBlocking {
        val temp = File(pgpUserDir, "aaa_staged.9${DirectoryBundler.TEMP_FILE_SUFFIX}")
        PgpKeys.savePublicKeyRingToFile(publicRing, temp.absolutePath)
        val keyId = repository.getKeys().single().publicKey.keyId

        assertIs<Outcome.Success<Unit>>(repository.deletePgpKey(keyId))

        assertTrue(temp.exists(), "staging files belong to their writers, not the delete scan")
        assertFalse(publicRingFile.exists())
        assertFalse(secretRingFile.exists())
    }

    @Test
    fun importBundledDeveloperKey_writesTheKeyIntoAFreshAccountDirAndListsItPublicOnly() = runBlocking {
        // Fresh account: no pgp dir at all yet — the import must create it (importPgpFile parity).
        pgpUserDir.deleteRecursively()

        val outcome = repository.importBundledDeveloperKey(force = false)

        assertEquals(true, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertEquals(BundledDeveloperKey.ARMOR, developerKeyFile.readText())

        val pair = repository.getKeys().single()
        assertEquals(BundledDeveloperKey.FINGERPRINT, pair.publicKey.fingerprint)
        assertEquals(PgpKeyType.Public, pair.publicKey.type)
        assertNull(pair.secretKey, "the bundled developer key must never come with a secret half")
        // Encrypt-to-developer availability: the certify-only primary carries an encryption subkey.
        assertTrue(pair.publicKey.isEncryptionKey || pair.publicKey.subKeys.any { it.isEncryptionKey })
        assertTrue("alice" in pgpPreferences.developerKeyImportedFor)
    }

    @Test
    fun importBundledDeveloperKey_secondCallIsAnAlreadyImportedSkip() = runBlocking {
        assertEquals(true, assertIs<Outcome.Success<Boolean>>(repository.importBundledDeveloperKey(force = false)).value)

        val second = repository.importBundledDeveloperKey(force = false)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(second).value)
        assertTrue(developerKeyFile.exists())
    }

    @Test
    fun importBundledDeveloperKey_deletionIsFinalForAutoImportButForceReimports() = runBlocking {
        repository.importBundledDeveloperKey(force = false)
        check(developerKeyFile.delete())

        // The user deleted the key: the once-per-account flag stays set, auto never resurrects it.
        val auto = repository.importBundledDeveloperKey(force = false)
        assertEquals(false, assertIs<Outcome.Success<Boolean>>(auto).value)
        assertFalse(developerKeyFile.exists())

        // The explicit menu action does re-import.
        val forced = repository.importBundledDeveloperKey(force = true)
        assertEquals(true, assertIs<Outcome.Success<Boolean>>(forced).value)
        assertEquals(BundledDeveloperKey.ARMOR, developerKeyFile.readText())
    }

    @Test
    fun importBundledDeveloperKey_refusesToOverwriteAForeignKeyAtTheDeveloperFileName() = runBlocking<Unit> {
        // Sync copies whatever a peer had under this name; neither auto nor force import may
        // destroy key material that is not the developer key.
        val foreignContent = writeForeignDeveloperKeyFile()

        val auto = repository.importBundledDeveloperKey(force = false)
        assertEquals(PgpFailure.ImportKeyFailure, assertIs<Outcome.Error>(auto).cause)

        val forced = repository.importBundledDeveloperKey(force = true)
        assertEquals(PgpFailure.ImportKeyFailure, assertIs<Outcome.Error>(forced).cause)

        assertEquals(foreignContent, developerKeyFile.readText(), "the occupant must stay intact")
        assertTrue(pgpPreferences.developerKeyImportedFor.isEmpty())
    }

    @Test
    fun importBundledDeveloperKey_treatsASyncedDeveloperKeyAsAlreadyImported() = runBlocking {
        // A peer synced the developer key here before this device's own auto-import ran.
        developerKeyFile.writeText(BundledDeveloperKey.ARMOR)

        val auto = repository.importBundledDeveloperKey(force = false)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(auto).value)
        assertTrue("alice" in pgpPreferences.developerKeyImportedFor)
        assertEquals(BundledDeveloperKey.ARMOR, developerKeyFile.readText())

        // The explicit action may still refresh the developer key's own file.
        val forced = repository.importBundledDeveloperKey(force = true)
        assertEquals(true, assertIs<Outcome.Success<Boolean>>(forced).value)
    }

    @Test
    fun importDeveloperKey_refusesWhenTheFingerprintDoesNotMatchThePin() = runBlocking<Unit> {
        // Tamper guard, exercised through the internal seam: same armor, wrong pin. Nothing may
        // be written and the once-per-account flag must NOT be recorded.
        val outcome = repository.importDeveloperKey(
            force = true,
            armor = BundledDeveloperKey.ARMOR,
            pinnedFingerprint = "0000000000000000000000000000000000000000",
        )

        assertEquals(PgpFailure.ImportKeyFailure, assertIs<Outcome.Error>(outcome).cause)
        assertFalse(developerKeyFile.exists())
        assertTrue(pgpPreferences.developerKeyImportedFor.isEmpty())
    }

    @Test
    fun importDeveloperKey_refusesArmorThatCarriesASecretRingEvenWithAMatchingPin() = runBlocking<Unit> {
        // Defense in depth: even a blob whose primary fingerprint matches is refused when it is
        // not exactly one public key ring — a secret ring must never install through this path.
        val armoredSecretRing = secretRingFile.readText()
        val itsOwnFingerprint = secretRing.secretKey.publicKey.fingerprint
            .joinToString("") { byte -> String.format("%02X", byte) }

        val outcome = repository.importDeveloperKey(
            force = true,
            armor = armoredSecretRing,
            pinnedFingerprint = itsOwnFingerprint,
        )

        assertEquals(PgpFailure.ImportKeyFailure, assertIs<Outcome.Error>(outcome).cause)
        assertFalse(developerKeyFile.exists())
        assertTrue(pgpPreferences.developerKeyImportedFor.isEmpty())
    }

    private fun writeCombinedRingFile(name: String) {
        File(pgpUserDir, name).outputStream().use { out ->
            publicRing.encode(out)
            secretRing.encode(out)
        }
    }

    /** A ring whose only key is a GNU-dummy stub: valid packets, no actual secret material. */
    private fun writeGnuDummySecretRing(name: String) {
        val dummyPacket = SecretKeyPacket(
            secretRing.secretKey.publicKey.publicKeyPacket,
            SymmetricKeyAlgorithmTags.NULL,
            SecretKeyPacket.USAGE_SHA1,
            S2K.gnuDummyS2K(S2K.GNUDummyParams.divertToCard()),
            null,
            null,
        )
        File(pgpUserDir, name).outputStream().use { out ->
            BCPGOutputStream(out).use { it.writePacket(dummyPacket) }
        }
    }

    /** A DIFFERENT key's valid public ring at the developer key's file name; returns its content. */
    private fun writeForeignDeveloperKeyFile(): String {
        val otherGenerator = PgpKeys.createPgpKeyRingGenerator(
            userId = "Other User <other@example.com>",
            algorithm = EDDSA,
            length = 256,
            expirationInSeconds = 0,
            password = "other-password",
        )
        PgpKeys.savePublicKeyRingToFile(otherGenerator.generatePublicKeyRing(), developerKeyFile.absolutePath)
        return developerKeyFile.readText()
    }

    private fun writeMultiKeySecretFile(name: String) {
        val otherGenerator = PgpKeys.createPgpKeyRingGenerator(
            userId = "Other User <other@example.com>",
            algorithm = EDDSA,
            length = 256,
            expirationInSeconds = 0,
            password = "other-password",
        )
        File(pgpUserDir, name).outputStream().use { out ->
            secretRing.encode(out)
            otherGenerator.generateSecretKeyRing().encode(out)
        }
    }

    private companion object {
        const val UNKNOWN_ALGORITHM_ID = 35
    }

}
