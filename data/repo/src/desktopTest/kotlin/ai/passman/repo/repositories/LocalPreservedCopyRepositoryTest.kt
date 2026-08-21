package ai.passman.repo.repositories

import ai.passman.domain.base.DefaultContextFacade
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The recovery screen's view of the conflict stores.
 *
 * What these pin, beyond plumbing: a [PreservedCopy.id] is a string that comes back from the UI and
 * is turned into a filesystem path used to delete files and choose a write destination. It gets
 * checked like any other untrusted path input, and that check is worth a test even though nothing
 * upstream is supposed to send anything strange.
 */
class LocalPreservedCopyRepositoryTest {

    private lateinit var localDir: File
    private lateinit var pgpDir: File
    private lateinit var repository: LocalPreservedCopyRepository
    private var loggedIn = true

    private inner class FakePlatform : Platform() {
        override fun getLocalPath(): String = localDir.absolutePath
    }

    private inner class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser =
            if (loggedIn) AppUser.LoggedIn("alice", Password("password", "salt")) else AppUser.Anonymous
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "preserved-copy-repository-test"
        override suspend fun clear() = Unit
    }

    @BeforeTest
    fun setUp() {
        localDir = Files.createTempDirectory("preserved-copy-repo-test").toFile()
        pgpDir = File(localDir, "pgp${File.separator}alice").apply { mkdirs() }
        loggedIn = true
        repository = LocalPreservedCopyRepository(
            platform = FakePlatform(),
            userPreferences = FakePreferences(),
            coroutinesContextFacade = DefaultContextFacade(),
        )
    }

    @AfterTest
    fun tearDown() {
        localDir.deleteRecursively()
    }

    @Test
    fun `lists what sync displaced`() = runBlocking {
        displaceRing()

        val copies = repository.list()

        assertEquals(1, copies.size)
        val copy = copies.single()
        assertEquals(SyncOps.PGP, copy.artifact)
        assertEquals("work_secret_ring.asc", copy.originalName)
        assertEquals(LOCAL.size.toLong(), copy.sizeBytes)
    }

    @Test
    fun `lists nothing when no sync has displaced anything`() = runBlocking {
        File(pgpDir, "work_secret_ring.asc").writeBytes(LOCAL)
        assertTrue(repository.list().isEmpty())
    }

    @Test
    fun `lists nothing without a logged-in user`() = runBlocking {
        displaceRing()
        loggedIn = false

        assertTrue(repository.list().isEmpty(), "there is no user whose artifacts these would be")
    }

    @Test
    fun `restores over the live artifact and keeps what it replaced`() = runBlocking {
        displaceRing()

        assertTrue(repository.restore(repository.list().single()))

        assertContentEquals(LOCAL, File(pgpDir, "work_secret_ring.asc").readBytes())
        assertContentEquals(INBOUND, repository.list().single().let { File(repository.pathOf(it)!!).readBytes() })
    }

    @Test
    fun `deletes permanently`() = runBlocking {
        displaceRing()
        val copy = repository.list().single()
        val path = repository.pathOf(copy)!!

        assertTrue(repository.delete(copy))

        assertFalse(File(path).exists())
        assertTrue(repository.list().isEmpty())
    }

    @Test
    fun `refuses an id that reaches a file outside the store`() = runBlocking {
        displaceRing()
        val real = repository.list().single()
        val live = File(pgpDir, "work_secret_ring.asc")
        val neighbour = File(localDir, "keystore${File.separator}alice").apply { mkdirs() }
            .let { File(it, "passman-keystore.pfx").apply { writeBytes(ByteArray(16) { 9 }) } }

        // Every one of these resolves to a file that genuinely exists, which is the point: an id
        // that merely fails to resolve proves nothing, since a missing file is refused anyway.
        // These name the live secret ring and a keystore in a sibling account directory — deleting
        // either would destroy the only copy of private key material.
        val forged = listOf(
            "..${File.separator}alice${File.separator}work_secret_ring.asc",
            "..${File.separator}..${File.separator}keystore${File.separator}alice${File.separator}passman-keystore.pfx",
            "..",
            ".",
            "",
        )
        for (id in forged) {
            val copy = real.copy(id = id)
            assertFalse(repository.delete(copy), "delete must refuse id '$id'")
            assertFalse(repository.restore(copy), "restore must refuse id '$id'")
            assertNull(repository.pathOf(copy), "pathOf must refuse id '$id'")
        }

        assertTrue(live.isFile, "the live secret ring must still exist")
        assertContentEquals(INBOUND, live.readBytes(), "and must be untouched")
        assertTrue(neighbour.isFile, "a file outside this artifact directory must be unreachable")
        assertEquals(1, repository.list().size, "the real preserved copy must be untouched")
    }

    @Test
    fun `an unrecognised artifact resolves to nothing`() = runBlocking {
        displaceRing()
        val forged = repository.list().single().copy(artifact = "artifact-from-a-newer-build")

        assertFalse(repository.delete(forged))
        assertFalse(repository.restore(forged))
        assertNull(repository.pathOf(forged))
    }

    /** Puts a ring live, then syncs a different one over it — the state the screen exists to show. */
    private fun displaceRing() {
        File(pgpDir, "work_secret_ring.asc").writeBytes(LOCAL)
        val bundle = ByteArrayOutputStream().also { out ->
            ZipOutputStream(out).use { zip ->
                zip.putNextEntry(ZipEntry("work_secret_ring.asc"))
                zip.write(INBOUND)
                zip.closeEntry()
            }
        }.toByteArray()
        DirectoryBundler.unbundle(bundle, pgpDir)
    }

    private companion object {
        val LOCAL = ByteArray(128) { 1 }
        val INBOUND = ByteArray(96) { 2 }
    }
}
