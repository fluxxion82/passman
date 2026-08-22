package ai.passman.platform.transfer

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The sync exclusion list is **resolved**, not compared as a string.
 *
 * The list is a set of names, but which file a name denotes is decided by the filesystem, and the
 * two disagree more often than a name comparison can see. Every disagreement below was a way for the
 * account's RSA identity — the key the vault is sealed under, of which nothing else holds a copy — to
 * be shipped to a peer or replaced by one.
 *
 * ## What these used to assert
 *
 * The opposite. This class was written as `IdentityStoreDisplaceableTest`, and its tests passed by
 * demonstrating the bypass: each carried the assertion that *would* hold if the exclusion did what
 * the design assumed, so that fixing it would fail them loudly rather than let them go quietly green
 * for a new reason. Resolving the comparison did exactly that, and this is the rewrite.
 *
 * ## Why a name comparison could not have worked
 *
 * - A username may have carried path syntax before sign-up refused it, so the exclusion string was
 *   `./alice.pfx` while the file's basename was `alice.pfx`.
 * - `ALICE.pfx` and `alice.pfx` are one file on APFS and NTFS.
 * - So are the two Unicode normal forms of an accented name, and nothing in this tree normalises.
 * - Windows folds `alice.pfx.` onto `alice.pfx`.
 *
 * Resolving both sides delegates the question to the thing that answers it. The name comparison is
 * kept alongside, because dropping it could only weaken the filter on a platform whose
 * canonicalisation does not fold the way its filesystem does.
 *
 * Sign-up now refuses such usernames outright, which closes the route in for anything created since.
 * These fixtures build the account directly, because the filter has to hold for an account created
 * *before* that rule too.
 */
class IdentityStoreExclusionTest {
    private lateinit var tempDir: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("identity-store-exclusion-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    /**
     * Inbound: a path-syntax account's identity store is not replaced by a peer's entry.
     *
     * `syncExclusions("./alice")` holds the string `./alice.pfx`; a peer sends the perfectly ordinary
     * entry `alice.pfx`; the basenames never matched, so the entry was staged, the live identity
     * store was displaced and the peer's file installed over it. Both spellings resolve to one path,
     * which is what now refuses it.
     */
    @Test
    fun aPathSyntaxAccountDoesNotAcceptAPeersIdentityStore() {
        val user = "./alice"
        val exclusions = DirectoryBundler.syncExclusions(user)
        assertTrue("alice.pfx" !in exclusions, "precondition: the name comparison alone still misses this")

        val destDir = File(tempDir, "keystore${File.separator}$user").apply { mkdirs() }
        val identityStore = File(destDir, "$user.pfx")
        identityStore.writeBytes(LOCAL_IDENTITY)

        // A second, ordinary entry rides along so this proves the unbundle RAN and skipped one file,
        // rather than passing because nothing was installed at all - discarding every entry would
        // otherwise satisfy every assertion below.
        DirectoryBundler.unbundle(
            zipOf("alice.pfx" to PEER_BYTES, "shared.p12" to PEER_BYTES),
            destDir,
            excludeBaseNames = exclusions,
        )

        assertContentEquals(
            PEER_BYTES,
            File(destDir, "shared.p12").readBytes(),
            "a non-excluded entry in the same bundle must have been installed",
        )
        assertContentEquals(
            LOCAL_IDENTITY,
            identityStore.readBytes(),
            "the identity store must survive an inbound entry that names it under another spelling",
        )
        assertTrue(
            DirectoryBundler.preservedCopies(destDir).isEmpty(),
            "an excluded entry is skipped before staging, so nothing is displaced at all",
        )
    }

    /**
     * Outbound, and this was the weaker of the two directions.
     *
     * `bundle` matched on `it.name !in excludeBaseNames` — exact, no folding, no trimming — so for
     * `./alice` the identity store was walked, matched nothing, and went into the bundle. That is the
     * account's RSA private key on the wire, which is worse than the inbound case: the inbound one
     * preserved what it displaced, this one simply hands the key to the peer.
     */
    @Test
    fun aPathSyntaxAccountDoesNotShipItsIdentityStore() {
        val user = "./alice"
        val sourceDir = File(tempDir, "keystore${File.separator}$user").apply { mkdirs() }
        File(sourceDir, "$user.pfx").writeBytes(LOCAL_IDENTITY)
        File(sourceDir, "shared.p12").writeBytes(PEER_BYTES)

        val entries = entryNames(DirectoryBundler.bundle(sourceDir, DirectoryBundler.syncExclusions(user)))

        assertEquals(listOf("shared.p12"), entries, "the identity store must never reach the bundle")
    }

    /**
     * A hard link to the identity store is not a way to ship it under another name.
     *
     * A hard link is an independent directory entry for the same inode, so `canonicalPath` returns
     * the link's own path and the name is whatever it was called — `shared.pfx` linked to
     * `alice.pfx` matched neither the name set nor the resolved set, and `bundle` zipped the RSA
     * private key under an innocent name. Only the filesystem's own identity for the file catches
     * it.
     *
     * Not an attack: creating one needs write access to the account directory, and anyone with that
     * could read the key outright. It is the accident that matters — a backup tool, a restore, or a
     * sync client that de-duplicates by linking, none of which know this file is special.
     *
     * Skipped where the platform reports no file key, since there is nothing to compare there.
     */
    @Test
    fun aHardLinkToTheIdentityStoreIsNotShipped() {
        val user = "alice"
        val dir = File(tempDir, "keystore${File.separator}$user").apply { mkdirs() }
        val identityStore = File(dir, "$user.pfx").apply { writeBytes(LOCAL_IDENTITY) }
        val link = File(dir, "shared.pfx")
        java.nio.file.Files.createLink(link.toPath(), identityStore.toPath())
        if (fileKeyOf(link) == null) return // platform reports no file key

        assertTrue(
            link.canonicalPath != identityStore.canonicalPath,
            "precondition: a hard link canonicalises to its own path, which is why this needs a key",
        )

        val entries = entryNames(DirectoryBundler.bundle(dir, DirectoryBundler.syncExclusions(user)))

        assertEquals(
            emptyList(),
            entries,
            "the identity store must not reach the bundle under a second name for the same inode",
        )
    }

    private fun fileKeyOf(file: File): Any? = runCatching {
        java.nio.file.Files.readAttributes(
            file.toPath(),
            java.nio.file.attribute.BasicFileAttributes::class.java,
        ).fileKey()
    }.getOrNull()

    /** The control: an ordinary account is unaffected, in both directions. */
    @Test
    fun anOrdinaryAccountStillExcludesItsIdentityStoreAndShipsEverythingElse() {
        val user = "alice"
        val exclusions = DirectoryBundler.syncExclusions(user)
        val dir = File(tempDir, "keystore${File.separator}$user").apply { mkdirs() }
        val identityStore = File(dir, "$user.pfx").apply { writeBytes(LOCAL_IDENTITY) }
        File(dir, "shared.p12").writeBytes(PEER_BYTES)

        assertEquals(
            listOf("shared.p12"),
            entryNames(DirectoryBundler.bundle(dir, exclusions)),
            "outbound: everything but the identity store",
        )

        DirectoryBundler.unbundle(zipOf("alice.pfx" to PEER_BYTES), dir, excludeBaseNames = exclusions)
        assertContentEquals(LOCAL_IDENTITY, identityStore.readBytes(), "inbound: untouched")
    }

    /**
     * A decomposed spelling of an accented account name is refused too.
     *
     * Two strings, one file on APFS and NTFS, and nothing in this tree normalises — so the exclusion
     * set built from the stored spelling never contained the other one. Skipped where the filesystem
     * keeps the two forms apart, because there is no collision to refuse there and a `check` would
     * fail the suite on Linux CI.
     */
    @Test
    fun aDecomposedSpellingOfAnAccentedAccountIsRefused() {
        val precomposed = "caf\u00E9" // NFC
        val decomposed = "cafe\u0301" // NFD; escaped so an editor cannot normalise it away
        check(precomposed.length + 1 == decomposed.length) { "two spellings, not one written twice" }
        val dir = File(tempDir, "keystore${File.separator}$precomposed").apply { mkdirs() }
        val identityStore = File(dir, "$precomposed.pfx").apply { writeBytes(LOCAL_IDENTITY) }
        if (!File(dir, "$decomposed.pfx").exists()) return // filesystem keeps the forms apart

        DirectoryBundler.unbundle(
            zipOf("$decomposed.pfx" to PEER_BYTES),
            dir,
            excludeBaseNames = DirectoryBundler.syncExclusions(precomposed),
        )

        assertContentEquals(
            LOCAL_IDENTITY,
            identityStore.readBytes(),
            "the other normal form names the same file and must be refused as the same file",
        )
        assertFalse(
            DirectoryBundler.preservedCopies(dir).isNotEmpty(),
            "and nothing may have been displaced",
        )
    }

    private fun entryNames(bundle: ByteArray): List<String> = buildList {
        ZipInputStream(bundle.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                add(entry.name)
                entry = zip.nextEntry
            }
        }
    }.sorted()

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private companion object {
        val LOCAL_IDENTITY = ByteArray(64) { 0x11 }
        val PEER_BYTES = ByteArray(64) { 0x22 }
    }
}
