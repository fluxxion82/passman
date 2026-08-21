package ai.passman.platform.transfer

import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.domain.user.ValidateSignUpCredentials
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The username rule and the storage layout have to agree, across a module boundary that stops them
 * from sharing a constant.
 *
 * `ValidateSignUpCredentials` refuses a username ending in a suffix that names a **sibling** of an
 * account's artifact directory — `<user>.conflicts`, `<user>.unbundle-staging`, `<user>.lock` — since
 * such a name would claim a path the app already uses for something that is not an account. It lives
 * in `domain`, the deepest module, and cannot see `DirectoryBundler` or `ArtifactDirectoryLock`,
 * which own the real strings. So it spells them itself, and this pins the two sides together.
 *
 * The same shape as `DirectoryBundlerSyncExclusionsTest` asserting that `TEMP_FILE_SUFFIX` equals
 * `IDENTITY_STORE_TEMP_SUFFIX`: a duplicated constant across a boundary is only safe while something
 * fails when the copies drift.
 *
 * Each suffix is **observed from the code that creates it**, and only then compared against the
 * literal. The literals are here — that is the point of a pin — but they are never the only thing
 * asserted: if `DirectoryBundler`'s constant moved, the observation would no longer equal the literal
 * and the sanity assertion fails; if `domain`'s copy moved, the observed suffix would no longer be
 * refused as a username and the rejection assertion fails. Drift in either direction breaks
 * something, which is the property a duplicated constant needs.
 *
 * The staging suffix is the exception and is spelled outright, because nothing exposes it: it is
 * checked by planting a marker at that path and watching `unbundle` wipe it.
 */
class UsernameFileSafetyTest {
    private val validate = ValidateSignUpCredentials()
    private lateinit var tempDir: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("username-file-safety-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun theConflictStoreSuffixIsRefusedAsAUsername() {
        val artifactDir = File(tempDir, ACCOUNT).apply { mkdirs() }

        val suffix = DirectoryBundler.conflictStore(artifactDir).name.removePrefix(ACCOUNT)

        assertEquals(".conflicts", suffix, "sanity: the observed suffix should look like one")
        assertRefusesUsernameEndingIn(suffix)
    }

    @Test
    fun theLockFileSuffixIsRefusedAsAUsername() {
        val artifactDir = File(tempDir, ACCOUNT).apply { mkdirs() }

        val suffix = ArtifactDirectoryLock.withLock(artifactDir) {
            val created = tempDir.listFiles().orEmpty().single { it.isFile && it.name.startsWith(ACCOUNT) }
            created.name.removePrefix(ACCOUNT)
        }

        assertEquals(".lock", suffix, "sanity: the observed suffix should look like one")
        assertRefusesUsernameEndingIn(suffix)
    }

    /**
     * The staging suffix, observed by the one behaviour that reveals it: `unbundle` wipes its staging
     * directory on entry, so a marker planted at that path does not survive.
     *
     * Indirect because nothing exposes the name — but it is the only way to read the real constant
     * rather than a second copy of it.
     */
    @Test
    fun theStagingSuffixIsRefusedAsAUsername() {
        val suffix = ".unbundle-staging"
        val artifactDir = File(tempDir, ACCOUNT).apply { mkdirs() }
        val marker = File(File(tempDir, "$ACCOUNT$suffix").apply { mkdirs() }, "marker")
            .apply { writeText("planted") }

        DirectoryBundler.unbundle(zipOf("ring.asc" to "bytes"), artifactDir)

        assertFalse(
            marker.exists(),
            "unbundle must have wiped its staging directory at this path — if it did not, the suffix " +
                "spelled here is no longer the one DirectoryBundler uses",
        )
        assertRefusesUsernameEndingIn(suffix)
    }

    private fun assertRefusesUsernameEndingIn(suffix: String) {
        val username = "alice$suffix"
        assertTrue(
            ValidateSignUpCredentials.Issue.UsernameHasIllegalCharacters in
                validate(username, STRONG_PASSWORD).issues,
            "\"$username\" would claim a path that is not an account directory, so sign-up must refuse it",
        )
    }

    private fun zipOf(vararg entries: Pair<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content.encodeToByteArray())
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private companion object {
        const val ACCOUNT = "alice"
        const val STRONG_PASSWORD = "Tr0ub4dor&3-correct-horse"
    }
}
