package ai.passman.platform.transfer

import ai.passman.keystore.KeystoreClient
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

class DirectoryBundlerSyncExclusionsTest {
    private lateinit var tempDir: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("directory-bundler-sync-exclusions-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun syncExclusions_containsIdentityPostQuantumAndRecoveryFiles() {
        assertEquals(
            setOf(
                "alice.pfx",
                "alice.pfx.bak",
                "alice.pfx.lock",
                "hybrid.key",
                "mldsa.key",
                "keyring.pmk",
                "keyring.pmk.next",
                "portable-recovery.pmk",
                "portable-recovery.previous",
                "alice.recovery.p12",
                "alice.recovery.crt",
            ),
            DirectoryBundler.syncExclusions("alice"),
        )
    }

    /**
     * The two constants that together make the exclusion set *provably* complete for
     * `keystore/<user>/`, asserted against the writer that actually names the files.
     *
     * `JvmKeyStoreClient.commitIdentityStore` creates exactly three things beside the store: the
     * replacement, `<user>.pfx.<random><temp suffix>`; the recovery copy, `<user>.pfx<backup suffix>`;
     * and the lock it meets a backup recovery on, `<user>.pfx<lock suffix>`. The first is caught by
     * [DirectoryBundler.TEMP_FILE_SUFFIX] and the other two by exact entries in
     * [DirectoryBundler.syncExclusions] — but only while the suffixes on the two sides of the module
     * boundary agree. Change one without the other and a file full of private key goes back on the
     * wire, silently, which is exactly what happened before the name was made deterministic.
     */
    @Test
    fun syncExclusions_agreeWithTheNamesTheIdentityStoreWriterUses() {
        assertEquals(
            DirectoryBundler.TEMP_FILE_SUFFIX,
            KeystoreClient.IDENTITY_STORE_TEMP_SUFFIX,
            "the suffix rule must match the suffix the identity-store commit writes",
        )
        assertTrue(
            KeystoreClient.identityStoreBackupName("alice.pfx") in DirectoryBundler.syncExclusions("alice"),
            "the identity-store backup must be excluded under the exact name the commit gives it",
        )
        assertTrue(
            KeystoreClient.identityStoreLockName("alice.pfx") in DirectoryBundler.syncExclusions("alice"),
            "the identity-store lock must be excluded under the exact name the commit gives it",
        )
    }

    /**
     * The identity store's lock file, in **both** directions.
     *
     * It is created by the first commit on an account and deliberately never deleted — unlinking a
     * lock file another process may hold open leaves the two of them locking different inodes, which
     * is no exclusion at all — so from then on it is a permanent resident of `keystore/<user>/`, the
     * directory a keystore sync bundles. Unlike the backup it holds no bytes, so this is not a leak;
     * it is a completeness property. [DirectoryBundler.syncExclusions] is only a *proof* that nothing
     * a commit writes can reach the wire while it lists everything a commit writes, and a peer's copy
     * arriving here is meaningless debris in a directory whose entire contents are supposed to be
     * accounted for.
     *
     * Outbound is asserted against the bundle itself rather than a round trip: `unbundle` applies the
     * same filter, so a round trip keeps passing with the outbound entry removed.
     */
    @Test
    fun syncExclusions_keepTheIdentityStoreLockOutOfBothDirections() {
        val lockName = KeystoreClient.identityStoreLockName("alice.pfx")
        val source = File(tempDir, "source").apply { mkdirs() }
        File(source, lockName).writeText("")
        File(source, "shared.key").writeText("shared")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val exclusions = DirectoryBundler.syncExclusions("alice")

        assertEquals(
            listOf("shared.key"),
            entryNames(DirectoryBundler.bundle(source, excludeBaseNames = exclusions)),
            "the identity-store lock must never reach the bundle",
        )

        DirectoryBundler.unbundle(
            zipOf(lockName to "", "shared.key" to "shared"),
            dest,
            excludeBaseNames = exclusions,
        )
        assertFalse(File(dest, lockName).exists(), "nor may a peer's copy be accepted")
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * The crash-debris leak — **outbound**, the direction that puts the private key on the wire.
     *
     * `commitIdentityStore` keeps a full copy of the live `.pfx` beside it while it swaps the
     * replacement in, and on a dual failure — the replace could not publish *and* the restore could not
     * put the original back — it deliberately leaves that copy on disk, because it is then the only
     * intact copy of the account's RSA identity. `keystore/<user>/` is the directory a keystore sync
     * bundles, so a stranded backup is this device's private identity key sitting in a sync source.
     *
     * `<user>.pfx` is excluded and `.tmp` is filtered by suffix, but the backup used to be
     * `<user>.pfx.<random>.bak` and matched neither: one interrupted commit and the next sync shipped
     * the key to a paired peer.
     *
     * Asserted against the bundle itself rather than against a round trip. `unbundle` applies the same
     * filter, so a round-trip assertion would keep passing with the outbound exclusion deleted while
     * every sync leaked — the failure mode this whole test file exists to catch, in miniature. Kept in
     * its own test from the inbound half for the same reason: one of them failing must not be able to
     * hide the other.
     */
    @Test
    fun syncExclusions_keepAStrandedIdentityStoreBackupOutOfTheBundle() {
        val backupName = KeystoreClient.identityStoreBackupName("alice.pfx")
        val source = File(tempDir, "source").apply { mkdirs() }
        File(source, backupName).writeText("alice's RSA identity, intact")
        File(source, "shared.key").writeText("shared")

        assertEquals(
            listOf("shared.key"),
            entryNames(DirectoryBundler.bundle(source, excludeBaseNames = DirectoryBundler.syncExclusions("alice"))),
            "a stranded identity-store backup must never reach the bundle",
        )
    }

    /**
     * The crash-debris leak — **inbound**.
     *
     * A hostile peer, or simply one running a build that predates the exclusion, will still send one.
     * Accepting it would drop another device's RSA identity into this account's keystore directory,
     * where the recovery path added alongside this could later restore it over the live store.
     *
     * The bundle is assembled by hand precisely because the local bundler no longer produces one.
     */
    @Test
    fun syncExclusions_refuseAnInboundIdentityStoreBackup() {
        val backupName = KeystoreClient.identityStoreBackupName("alice.pfx")
        val dest = File(tempDir, "dest").apply { mkdirs() }

        DirectoryBundler.unbundle(
            zipOf(backupName to "a peer's RSA identity", "shared.key" to "shared"),
            dest,
            excludeBaseNames = DirectoryBundler.syncExclusions("alice"),
        )

        assertFalse(File(dest, backupName).exists(), "a peer's identity-store backup must never be written here")
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * The pending keyring generation a password change stages before it commits.
     *
     * It carries the same device master key as the live keyring, so every reason that one is
     * excluded applies unchanged — plus one of its own: the next login *promotes* a staged
     * generation, so a peer's copy unbundled over this device's would become this device's live
     * keyring, wrapped under a password typed on another machine.
     */
    @Test
    fun syncExclusions_keepTheStagedKeyringGenerationOutOfBothDirections() {
        val source = File(tempDir, "source").apply { mkdirs() }
        File(source, DirectoryBundler.KEYRING_STAGED_FILE_NAME).writeText("sender-staged")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val localStaged = File(dest, DirectoryBundler.KEYRING_STAGED_FILE_NAME).apply { writeText("local-staged") }
        val exclusions = DirectoryBundler.syncExclusions("alice")

        DirectoryBundler.unbundle(DirectoryBundler.bundle(source, excludeBaseNames = exclusions), dest)
        assertContentEquals("local-staged".encodeToByteArray(), localStaged.readBytes())

        DirectoryBundler.unbundle(DirectoryBundler.bundle(source), dest, excludeBaseNames = exclusions)
        assertContentEquals("local-staged".encodeToByteArray(), localStaged.readBytes())
    }

    /**
     * The keyring wraps this device's master key, from which the identity-store password and every
     * key-file key are derived. Sending it would hand a peer the ability to open this device's `.pfx`
     * and key files; accepting a peer's would replace the local master key and orphan everything
     * sealed under it. Both directions have to filter it, which is why this asserts both.
     */
    @Test
    fun syncExclusions_keepTheDeviceKeyringOutOfBothDirections() {
        val source = File(tempDir, "source").apply { mkdirs() }
        File(source, DirectoryBundler.KEYRING_FILE_NAME).writeText("sender-keyring")
        File(source, "shared.key").writeText("shared")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val localKeyring = File(dest, DirectoryBundler.KEYRING_FILE_NAME).apply { writeText("local-keyring") }
        val exclusions = DirectoryBundler.syncExclusions("alice")

        // Outbound: the keyring is not in the bundle at all.
        val filteredBundle = DirectoryBundler.bundle(source, excludeBaseNames = exclusions)
        DirectoryBundler.unbundle(filteredBundle, dest)
        assertContentEquals("local-keyring".encodeToByteArray(), localKeyring.readBytes())

        // Inbound: even a hostile or older peer that did send one cannot overwrite the local keyring.
        DirectoryBundler.unbundle(DirectoryBundler.bundle(source), dest, excludeBaseNames = exclusions)
        assertContentEquals("local-keyring".encodeToByteArray(), localKeyring.readBytes())
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * A publishing temp file left behind by a power cut, in the directory this object bundles.
     *
     * `KeyringStore.writeDurably` and both key managers create their temp inside `keystore/<user>/`,
     * because the rename that follows has to stay on one filesystem — and that is exactly the
     * directory a keystore sync bundles. Lose power between the write and the rename and a file full
     * of wrapped master key is sitting in a sync source. [DirectoryBundler.syncExclusions] cannot
     * catch it: those are exact basenames and `File.createTempFile` puts a random infix in the middle,
     * so `keyring.pmk.5481093.tmp` matches nothing in the set.
     *
     * Both directions, because a peer running an older build will still send one.
     */
    @Test
    fun syncExclusions_keepPublishingTempFilesOutOfBothDirections() {
        val source = File(tempDir, "source").apply { mkdirs() }
        val temp = File(source, "${DirectoryBundler.KEYRING_FILE_NAME}.5481093${DirectoryBundler.TEMP_FILE_SUFFIX}")
            .apply { writeText("half-written master key") }
        File(source, "shared.key").writeText("shared")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val exclusions = DirectoryBundler.syncExclusions("alice")

        assertEquals(
            emptyList(),
            exclusions.filter { it == temp.name },
            "precondition: the basename set cannot match a temp name, which is why the suffix rule exists",
        )

        // Outbound, asserted against the bundle itself rather than against a round trip: unbundling
        // applies the same filter, so a round trip would keep passing with the outbound half removed
        // and would quietly stop covering the direction that actually puts key material on the wire.
        assertEquals(
            listOf("shared.key"),
            entryNames(DirectoryBundler.bundle(source, excludeBaseNames = exclusions)),
            "a publishing temp must never reach the bundle",
        )

        // Inbound: a peer running the previous build did not filter, and its bundle must still not
        // land one here. Assembled by hand precisely because the local bundler no longer produces it.
        DirectoryBundler.unbundle(
            zipOf(temp.name to "half-written master key", "shared.key" to "shared"),
            dest,
            excludeBaseNames = exclusions,
        )
        assertFalse(File(dest, temp.name).exists(), "nor may one be accepted")
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
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

    /** A bundle exactly as an older peer would have produced it, unfiltered. */
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

    /**
     * The two post-quantum private key files, in **both** directions.
     *
     * The inbound half already had coverage; the outbound half never did, and it is the half that
     * puts private key bytes on the wire. Both are asserted here because the round-trip shape used
     * below hides an outbound regression completely — `unbundle` applies the same filter, so deleting
     * the exclusion from `bundle` alone keeps every round-trip assertion green while every sync ships
     * this device's ML-KEM and ML-DSA private keys to its peer.
     *
     * The inbound half is not belt-and-braces either: it was added to fix a real bug where a peer's
     * copy clobbered the local key. Since these files now hang off the device master key rather than
     * the vault, an accepted foreign copy is not even decryptable here — the failure shows up as sync
     * breaking after a restart, pointing at nothing.
     */
    @Test
    fun syncExclusions_keepThePostQuantumKeyFilesOutOfBothDirections() {
        val source = File(tempDir, "source").apply { mkdirs() }
        File(source, DirectoryBundler.HYBRID_KEY_FILE_NAME).writeText("sender-hybrid")
        File(source, DirectoryBundler.ML_DSA_KEY_FILE_NAME).writeText("sender-mldsa")
        File(source, "shared.key").writeText("shared")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val localHybrid = File(dest, DirectoryBundler.HYBRID_KEY_FILE_NAME).apply { writeText("local-hybrid") }
        val localMlDsa = File(dest, DirectoryBundler.ML_DSA_KEY_FILE_NAME).apply { writeText("local-mldsa") }
        val exclusions = DirectoryBundler.syncExclusions("alice")

        // Outbound, asserted against the bundle itself: a round trip would keep passing with the
        // outbound filter removed, and outbound is the direction that leaks the private keys.
        assertEquals(
            listOf("shared.key"),
            entryNames(DirectoryBundler.bundle(source, excludeBaseNames = exclusions)),
            "neither private key file may reach the bundle",
        )

        // Inbound: a hostile or older peer that did send them must not overwrite the local ones.
        DirectoryBundler.unbundle(DirectoryBundler.bundle(source), dest, excludeBaseNames = exclusions)
        assertContentEquals("local-hybrid".encodeToByteArray(), localHybrid.readBytes())
        assertContentEquals("local-mldsa".encodeToByteArray(), localMlDsa.readBytes())
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * The four portable-vault-recovery artifacts `JvmPortableVaultRecovery` keeps in
     * `keystore/<user>/` — the directory a keystore sync bundles — in **both** directions.
     *
     * `portable-recovery.pmk` is the record holding the recovery password and certificate pin,
     * sealed under this device's master key: a peer's copy is ciphertext the receiving keyring can
     * never open, so unbundling one over the local record silently breaks the receiver's portable
     * recovery — discovered only when the user actually needs it. `<user>.recovery.p12` and
     * `<user>.recovery.crt` are that device's own recovery keypair; a foreign pair fails the record's
     * certificate pin, and on a device that has not created recovery material yet their mere presence
     * wedges creation permanently (`create()` refuses while either file exists).
     * `portable-recovery.previous` is the pre-upgrade P12 the phrase upgrade can strand, and the
     * legacy-open path will try to restore whatever sits at that name over the live P12.
     *
     * Outbound is asserted against the bundle itself rather than a round trip — `unbundle` applies
     * the same filter, so a round trip would keep passing with the outbound half removed — and
     * outbound also ships a complete (password-encrypted) copy of the sender's recovery private key,
     * which has no business on the wire.
     */
    @Test
    fun syncExclusions_keepThePortableRecoveryArtifactsOutOfBothDirections() {
        val recoveryNames = listOf(
            DirectoryBundler.PORTABLE_RECOVERY_RECORD_FILE_NAME,
            DirectoryBundler.PORTABLE_RECOVERY_BACKUP_FILE_NAME,
            DirectoryBundler.portableRecoveryP12Name("alice"),
            DirectoryBundler.portableRecoveryCertificateName("alice"),
        )
        val source = File(tempDir, "source").apply { mkdirs() }
        recoveryNames.forEach { File(source, it).writeText("sender-$it") }
        File(source, "shared.key").writeText("shared")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val localCopies = recoveryNames.map { File(dest, it).apply { writeText("local-$it") } }
        val exclusions = DirectoryBundler.syncExclusions("alice")

        // Outbound: none of the recovery artifacts may reach the bundle.
        assertEquals(
            listOf("shared.key"),
            entryNames(DirectoryBundler.bundle(source, excludeBaseNames = exclusions)),
            "no portable-recovery artifact may reach the bundle",
        )

        // Inbound: a hostile or older peer that did send them must not overwrite the local ones.
        DirectoryBundler.unbundle(DirectoryBundler.bundle(source), dest, excludeBaseNames = exclusions)
        localCopies.forEach { local ->
            assertContentEquals(
                "local-${local.name}".encodeToByteArray(),
                local.readBytes(),
                "a peer's ${local.name} must never overwrite the local one",
            )
        }
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * Inbound, on a device that has no recovery material yet — the half the overwrite test above
     * cannot catch. `JvmPortableVaultRecovery.create` refuses to run while `<user>.recovery.p12` or
     * `<user>.recovery.crt` exists ("portable recovery material is incomplete"), so a peer's copy
     * landing in an empty directory does not just sit there as debris: it permanently wedges
     * recovery creation on this device until someone deletes the file by hand.
     */
    @Test
    fun syncExclusions_refuseInboundRecoveryArtifactsIntoAnEmptyDirectory() {
        val recoveryNames = listOf(
            DirectoryBundler.PORTABLE_RECOVERY_RECORD_FILE_NAME,
            DirectoryBundler.PORTABLE_RECOVERY_BACKUP_FILE_NAME,
            DirectoryBundler.portableRecoveryP12Name("alice"),
            DirectoryBundler.portableRecoveryCertificateName("alice"),
        )
        val dest = File(tempDir, "dest").apply { mkdirs() }

        DirectoryBundler.unbundle(
            zipOf(*recoveryNames.map { it to "a peer's $it" }.toTypedArray(), "shared.key" to "shared"),
            dest,
            excludeBaseNames = DirectoryBundler.syncExclusions("alice"),
        )

        recoveryNames.forEach { name ->
            assertFalse(File(dest, name).exists(), "a peer's $name must never be written here")
        }
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * Case-variant inbound entries. `unbundle` writes into whatever filesystem the app runs on, and
     * the filesystems desktop actually ships to — APFS and NTFS in their default configurations —
     * are case-insensitive: `Alice.recovery.p12` opens the very file `alice.recovery.p12` names. An
     * exact, case-sensitive comparison is therefore a bypass of the entire exclusion set for any
     * hostile or merely case-mangled peer entry, so the basename must be compared as the destination
     * filesystem resolves it, not as the zip spells it.
     *
     * The certificate probe uses a name with no local counterpart, so its `exists()` check is
     * unambiguous on both case-sensitive and case-insensitive filesystems; the other three assert
     * that the local file survived, which is the half only a case-insensitive filesystem can fail.
     */
    @Test
    fun syncExclusions_refuseCaseVariantInboundEntries() {
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val localRecord = File(dest, DirectoryBundler.PORTABLE_RECOVERY_RECORD_FILE_NAME)
            .apply { writeText("local-record") }
        val localP12 = File(dest, DirectoryBundler.portableRecoveryP12Name("alice"))
            .apply { writeText("local-p12") }
        val localIdentity = File(dest, "alice.pfx").apply { writeText("local-identity") }

        DirectoryBundler.unbundle(
            zipOf(
                "PORTABLE-RECOVERY.PMK" to "a peer's record",
                "Alice.recovery.p12" to "a peer's recovery key",
                "ALICE.PFX" to "a peer's identity",
                "Alice.Recovery.CRT" to "a peer's certificate",
                "shared.key" to "shared",
            ),
            dest,
            excludeBaseNames = DirectoryBundler.syncExclusions("alice"),
        )

        assertContentEquals("local-record".encodeToByteArray(), localRecord.readBytes())
        assertContentEquals("local-p12".encodeToByteArray(), localP12.readBytes())
        assertContentEquals("local-identity".encodeToByteArray(), localIdentity.readBytes())
        assertFalse(
            File(dest, "Alice.Recovery.CRT").exists(),
            "a case-variant of an excluded name must be skipped, not written",
        )
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    /**
     * Windows filename normalization: NTFS strips trailing dots and spaces at open, so
     * `alice.recovery.p12.` and `keyring.pmk ` resolve to the excluded names on a platform this app
     * ships to. The basename is trimmed of trailing `.` and ` ` before the comparison so the zip
     * spelling cannot dodge the set; the entry is skipped outright rather than written under its
     * literal name, because debris one filesystem quietly folds onto a protected file is not worth
     * keeping anywhere.
     */
    @Test
    fun syncExclusions_refuseTrailingDotAndSpaceVariantInboundEntries() {
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val localP12 = File(dest, DirectoryBundler.portableRecoveryP12Name("alice"))
            .apply { writeText("local-p12") }
        val localKeyring = File(dest, DirectoryBundler.KEYRING_FILE_NAME).apply { writeText("local-keyring") }

        DirectoryBundler.unbundle(
            zipOf(
                "alice.recovery.p12." to "a peer's recovery key",
                "keyring.pmk " to "a peer's keyring",
                "shared.key" to "shared",
            ),
            dest,
            excludeBaseNames = DirectoryBundler.syncExclusions("alice"),
        )

        assertContentEquals("local-p12".encodeToByteArray(), localP12.readBytes())
        assertContentEquals("local-keyring".encodeToByteArray(), localKeyring.readBytes())
        assertFalse(
            File(dest, "alice.recovery.p12.").exists(),
            "a trailing-dot variant of an excluded name must be skipped, not written",
        )
        assertFalse(
            File(dest, "keyring.pmk ").exists(),
            "a trailing-space variant of an excluded name must be skipped, not written",
        )
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }

    @Test
    fun unbundle_syncExclusions_preservesExistingHybridKey() {
        val source = File(tempDir, "source").apply { mkdirs() }
        File(source, "hybrid.key").writeText("sender-key")
        File(source, "shared.key").writeText("shared")
        val dest = File(tempDir, "dest").apply { mkdirs() }
        val receiverHybrid = File(dest, "hybrid.key").apply { writeText("receiver-key") }

        DirectoryBundler.unbundle(
            DirectoryBundler.bundle(source),
            dest,
            excludeBaseNames = DirectoryBundler.syncExclusions("alice"),
        )

        assertContentEquals("receiver-key".encodeToByteArray(), receiverHybrid.readBytes())
        assertContentEquals("shared".encodeToByteArray(), File(dest, "shared.key").readBytes())
    }
}
