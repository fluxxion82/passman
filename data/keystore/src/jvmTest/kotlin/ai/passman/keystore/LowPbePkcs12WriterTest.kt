package ai.passman.keystore

import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.keystore.model.Keystore
import ai.passman.logging.KLogger
import ai.passman.logging.Logger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
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
import kotlin.test.fail
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBMPString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe
import org.bouncycastle.asn1.pkcs.EncryptedData
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.Pfx
import org.bouncycastle.asn1.pkcs.SafeBag
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder

/**
 * The identity store's PKCS#12 parameters, and the fence around them.
 *
 * Two things are under test and the second matters more than the first. One: an identity store is
 * written at [LowPbePkcs12Writer.ITERATIONS], survives a password change and a re-encode with every
 * entry and every key intact, and is still readable by SUN, by BouncyCastle and by the production
 * read path. Two: **nothing else is.** A keystore the tools UI creates is sealed with a password a
 * human chose, its iteration count is the only thing that makes guessing that password expensive,
 * and the leak this file exists to catch is the day those two writers become one.
 */
class LowPbePkcs12WriterTest {

    private lateinit var directory: File
    private val client = JvmKeyStoreClient()

    @BeforeTest
    fun setUp() {
        directory = Files.createTempDirectory("low-pbe-writer").toFile()
    }

    @AfterTest
    fun tearDown() {
        Files.setPosixFilePermissions(directory.toPath(), ALL_OWNER_PERMISSIONS)
        directory.deleteRecursively()
    }

    // ------------------------------------------------------------------- creation

    @Test
    fun `creating an identity store writes PBES2 AES256 at the low iteration count with a SHA-256 MAC`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())

        val profile = profileOf(identityStore().readBytes())
        assertEquals(
            LowPbePkcs12Writer.ITERATIONS,
            profile.keyIterations,
            "the key bag must be written at the low count; the whole point is that login stops paying for it",
        )
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.certificateIterations)
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.macIterations)
        assertEquals(PKCSObjectIdentifiers.id_PBES2, profile.keyAlgorithm)
        assertEquals(PKCSObjectIdentifiers.id_PBES2, profile.certificateAlgorithm)
        assertEquals(NISTObjectIdentifiers.id_aes256_CBC, profile.keyEncryptionScheme)
        assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, profile.keyPrf)
        assertEquals(NISTObjectIdentifiers.id_sha256, profile.macDigest)
    }

    @Test
    fun `an identity store is readable by SUN by BouncyCastle and by the production key path`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val bytes = identityStore().readBytes()

        val viaBouncyCastle = assertNotNull(load(bytes, "BC").getKey(ALIAS, PASSWORD.toCharArray()))
        withBouncyCastleDemoted {
            assertContentEquals(
                viaBouncyCastle.encoded,
                assertNotNull(load(bytes, "SUN").getKey(ALIAS, PASSWORD.toCharArray())).encoded,
                "stock SUN must read the same private key — the desktop app prefers it",
            )
        }

        val loaded = client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow()
        assertContentEquals(
            viaBouncyCastle.encoded,
            assertNotNull(client.unwrapKey(loaded, ALIAS, PASSWORD.toCharArray())).encoded,
            "the production unwrap path must return the same private key",
        )
        assertNotNull(loaded.getCertificate(ALIAS), "the certificate must stay associated with the key")
    }

    @Test
    fun `a wrong password does not open a low-PBE identity store`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())

        assertNull(client.getKeyStoreInfo(descriptor("not-the-derived-password")).getOrNull())
    }

    // ------------------------------------------------------------------- password change

    @Test
    fun `changing the identity store password keeps the low parameters the aliases and the key`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val original = assertNotNull(
            client.unwrapKey(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow(), ALIAS, PASSWORD.toCharArray()),
        )

        val outcome = client.changeIdentityKeyStorePassword(directory.absolutePath, FILE_NAME, PASSWORD, SECOND_STORE_PASSWORD)

        assertIs<Outcome.Success<Unit>>(outcome)
        val profile = profileOf(identityStore().readBytes())
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.keyIterations)
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.certificateIterations)
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.macIterations)
        val rekeyed = client.getKeyStoreInfo(descriptor(SECOND_PASSWORD)).getOrThrow()
        assertEquals(setOf(ALIAS.lowercase()), rekeyed.aliases().toList().map(String::lowercase).toSet())
        assertContentEquals(
            original.encoded,
            assertNotNull(client.unwrapKey(rekeyed, ALIAS, SECOND_PASSWORD.toCharArray())).encoded,
            "the re-keyed store must hold the SAME private key, not a fresh one",
        )
        assertNull(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrNull(), "the old password must not open it")
    }

    /**
     * A migration whose old password is wrong is the ordinary "this store is already migrated"
     * answer, not a reason to touch the only copy of an account's RSA identity.
     */
    @Test
    fun `changing the identity store password with the wrong old password leaves the file byte-identical`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val before = identityStore().readBytes()

        val outcome = client.changeIdentityKeyStorePassword(directory.absolutePath, FILE_NAME, "wrong", SECOND_STORE_PASSWORD)

        assertIs<Outcome.Error>(outcome)
        assertContentEquals(before, identityStore().readBytes())
        assertNotNull(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrNull())
    }

    // ------------------------------------------------------------------- re-encode

    @Test
    fun `re-encoding rewrites a BouncyCastle-default store and keeps every entry and every key`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        identityStore().writeBytes(bouncyCastleDefaultStore(keyPair))
        assertTrue(profileOf(identityStore().readBytes()).keyIterations > 10_000, "fixture precondition")

        val outcome = client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD)

        assertIs<Outcome.Success<Unit>>(outcome)
        val profile = profileOf(identityStore().readBytes())
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.keyIterations)
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.certificateIterations)
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.macIterations)
        val reloaded = client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow()
        assertEquals(setOf(ALIAS.lowercase()), reloaded.aliases().toList().map(String::lowercase).toSet())
        assertContentEquals(
            keyPair.private.encoded,
            assertNotNull(client.unwrapKey(reloaded, ALIAS, PASSWORD.toCharArray())).encoded,
            "re-encoding must move the same private key, not mint a new one",
        )
    }

    @Test
    fun `re-encoding a store that is already low does not rewrite the file`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val before = identityStore().readBytes()

        assertIs<Outcome.Success<Unit>>(client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD))

        // Byte equality is the assertion: a rewrite would re-salt PBKDF2 and change every byte, so
        // this fails the moment the hasLegacyPbe gate stops short-circuiting.
        assertContentEquals(before, identityStore().readBytes(), "an already-low store must not be rewritten")
    }

    @Test
    fun `re-encoding with a password that does not open the store leaves the file byte-identical`() {
        identityStore().writeBytes(bouncyCastleDefaultStore(KeyPairGenerator.getInstance("RSA").generateKeyPair()))
        val before = identityStore().readBytes()

        val outcome = client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, IdentityStorePassword.unsafeNotFromKeyring("not the store password"))

        assertIs<Outcome.Error>(outcome)
        assertContentEquals(before, identityStore().readBytes())
    }

    /**
     * The crash window. Nothing may be published until the replacement has been read back, so a
     * failure anywhere before the swap has to leave the original openable and the account usable —
     * and the next attempt has to finish the job.
     */
    @Test
    fun `a re-encode that cannot publish leaves the original store intact and the next attempt completes it`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        identityStore().writeBytes(bouncyCastleDefaultStore(keyPair))
        val before = identityStore().readBytes()
        // No new file can be created in the directory, so the write of the replacement fails before
        // anything is swapped in — the same shape as a crash between the encode and the rename.
        Files.setPosixFilePermissions(directory.toPath(), setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE))

        val interrupted = client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD)

        assertIs<Outcome.Error>(interrupted)
        assertContentEquals(before, identityStore().readBytes(), "the original must be untouched")
        assertNotNull(
            client.unwrapKey(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow(), ALIAS, PASSWORD.toCharArray()),
            "the original must still open and unwrap",
        )
        assertEquals(
            listOf(FILE_NAME),
            directory.list()?.toList(),
            "a failed publish must not leave debris beside the store",
        )

        Files.setPosixFilePermissions(directory.toPath(), ALL_OWNER_PERMISSIONS)
        assertIs<Outcome.Success<Unit>>(client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD))
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profileOf(identityStore().readBytes()).keyIterations)
        assertContentEquals(
            keyPair.private.encoded,
            assertNotNull(client.unwrapKey(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow(), ALIAS, PASSWORD.toCharArray())).encoded,
        )
    }

    // ------------------------------------------------------------------- encode

    @Test
    fun `encode carries a certificate-only entry across`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val source = KeyStore.getInstance("PKCS12", "BC").apply {
            load(null, PASSWORD.toCharArray())
            setKeyEntry(ALIAS, keyPair.private, PASSWORD.toCharArray(), arrayOf(trustedCertificate()))
            setCertificateEntry(TRUSTED_ALIAS, trustedCertificate())
        }

        val encoded = LowPbePkcs12Writer.encode(source, PASSWORD.toCharArray())

        val reloaded = load(encoded, "BC")
        assertEquals(
            setOf(ALIAS.lowercase(), TRUSTED_ALIAS.lowercase()),
            reloaded.aliases().toList().map(String::lowercase).toSet(),
            "a certificate-only entry must not be dropped",
        )
        assertTrue(reloaded.isCertificateEntry(TRUSTED_ALIAS))
        withBouncyCastleDemoted {
            val viaSun = load(encoded, "SUN")
            assertTrue(viaSun.isCertificateEntry(TRUSTED_ALIAS), "SUN must read it back as a trusted certificate too")
            assertContentEquals(trustedCertificate().encoded, viaSun.getCertificate(TRUSTED_ALIAS).encoded)
        }
    }

    /**
     * Dropping an entry this writer cannot represent would be silent, permanent data loss on the one
     * file an account cannot regenerate. It throws instead.
     */
    @Test
    fun `encode refuses a store holding a secret key rather than dropping it`() {
        // BC's PKCS12 rejects secret keys outright, so the unrepresentable entry is built in a JCEKS
        // store — the point is what `encode` does when handed one, not where it came from.
        val jceks = KeyStore.getInstance("JCEKS").apply {
            load(null, PASSWORD.toCharArray())
            setKeyEntry("secret", KeyService.createAESKey(), PASSWORD.toCharArray(), null)
        }

        assertFailsWith<IllegalStateException> { LowPbePkcs12Writer.encode(jceks, PASSWORD.toCharArray()) }
    }

    @Test
    fun `encode refuses a key with no certificate chain rather than writing an unusable entry`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()

        assertFailsWith<IllegalArgumentException> {
            LowPbePkcs12Writer.encode(ALIAS, keyPair.private, emptyList(), PASSWORD.toCharArray())
        }
    }

    // ------------------------------------------------------------------- sniff

    @Test
    fun `hasLegacyPbe is true for a BouncyCastle-default store`() {
        assertTrue(LowPbePkcs12Writer.hasLegacyPbe(bouncyCastleDefaultStore(KeyPairGenerator.getInstance("RSA").generateKeyPair())))
    }

    @Test
    fun `hasLegacyPbe is false for a store this writer produced`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())

        assertFalse(LowPbePkcs12Writer.hasLegacyPbe(identityStore().readBytes()))
    }

    @Test
    fun `hasLegacyPbe answers false for bytes it cannot parse instead of throwing`() {
        assertFalse(LowPbePkcs12Writer.hasLegacyPbe(ByteArray(0)))
        assertFalse(LowPbePkcs12Writer.hasLegacyPbe("not a pfx at all".encodeToByteArray()))
        assertFalse(LowPbePkcs12Writer.hasLegacyPbe(ByteArray(512) { it.toByte() }))
    }

    /**
     * **The MAC is half the cost, and it is paid separately from the bags.**
     *
     * A PKCS#12's file MAC has its own algorithm and its own iteration count, and opening the store
     * pays it in full before a single bag is touched. BouncyCastle writes SHA-1 at 1,200,000 there —
     * on its own, more work than everything else in the file put together. So a store can carry
     * perfectly cheap bags and still cost seconds to open, and that store *does* need rewriting.
     *
     * Nothing else in this class covers it: every other legacy fixture has expensive bags too, so the
     * bag check alone answers them all and the MAC check is dead weight as far as they are concerned.
     * This is the one that fails if it is deleted.
     */
    @Test
    fun `hasLegacyPbe is true for cheap bags under an expensive SHA-1 MAC`() {
        val store = lowBagsExpensiveMacStore(KeyPairGenerator.getInstance("RSA").generateKeyPair())

        val profile = profileOf(store)
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.keyIterations, "fixture: the bags must be cheap")
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profile.certificateIterations, "fixture: the bags must be cheap")
        assertEquals(1_200_000, profile.macIterations, "fixture: the MAC must be BouncyCastle's own default")

        assertTrue(
            LowPbePkcs12Writer.hasLegacyPbe(store),
            "an expensive MAC is expensive whatever the bags cost, and login pays it on every open",
        )
    }

    /**
     * The JDK's own defaults are *not* legacy, and rewriting them would be churn against the one file
     * an account cannot regenerate.
     *
     * A desktop migration lands here — SUN writes 10,000 everywhere on JDK 17 — and 10,000 iterations
     * of PBKDF2 is a few milliseconds, not the seconds BouncyCastle's 600,000/1,200,000 costs. The
     * threshold sits exactly on this number so that this store is left alone, and this test is what
     * pins that: raise the threshold above the SUN default and stores stop being rewritten that should
     * be; lower it and every desktop account rewrites its private key for nothing.
     */
    @Test
    fun `hasLegacyPbe is false for a store written by stock SUN at its own defaults`() {
        val store = sunDefaultStore(KeyPairGenerator.getInstance("RSA").generateKeyPair())

        val profile = profileOf(store)
        assertEquals(
            listOf(10_000, 10_000, 10_000),
            listOf(profile.keyIterations, profile.certificateIterations, profile.macIterations),
            "fixture: this is JDK 17's SUN PKCS#12 profile, and the whole point is that it is left alone",
        )

        assertFalse(LowPbePkcs12Writer.hasLegacyPbe(store), "a SUN-written store is cheap enough already")
    }

    /**
     * The read is bounded, and each side of the bound answers in the direction that changes nothing.
     *
     * These run on the login path against a file whose size this code does not control. An identity
     * store is a few kilobytes; anything vastly larger at that path is not one, and login must neither
     * pull it into memory nor fail because of it.
     *
     * The two answers point opposite ways on purpose, because "safe" means different things for the
     * two questions, and that is also what makes the cap observable: for a file this cannot vouch for,
     * `hasLegacyPbe` says "not legacy" so nothing is rewritten, and `isStructurallyPkcs12` says
     * "present" so nothing is restored over it. Delete the cap and the second answer flips — the bytes
     * get read, fail to parse, and a backup becomes eligible to overwrite a file nobody has
     * identified.
     */
    @Test
    fun `an implausibly large file is not read, and each answer errs towards touching nothing`() {
        val oversized = File(directory, "oversized.pfx")
        RandomAccessFile(oversized, "rw").use { it.setLength(5L * 1024 * 1024) }

        assertFalse(
            LowPbePkcs12Writer.hasLegacyPbe(oversized),
            "over the cap must never mean 'rewrite this', and never a throw",
        )
        assertTrue(
            LowPbePkcs12Writer.isStructurallyPkcs12(oversized),
            "over the cap must never mean 'this is damaged, overwrite it from a backup'",
        )
    }

    @Test
    fun `hasLegacyPbe on a file agrees with hasLegacyPbe on its bytes`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        assertFalse(LowPbePkcs12Writer.hasLegacyPbe(identityStore()))

        identityStore().writeBytes(bouncyCastleDefaultStore(KeyPairGenerator.getInstance("RSA").generateKeyPair()))
        assertTrue(LowPbePkcs12Writer.hasLegacyPbe(identityStore()))

        assertFalse(LowPbePkcs12Writer.hasLegacyPbe(File(directory, "not-here.pfx")), "a missing file is not legacy")
    }

    // ------------------------------------------------------------------- the recovery copy

    /**
     * A commit's recovery copy has one well-known name, and that is a security property.
     *
     * It used to be `File.createTempFile("<name>.", ".bak")`, i.e. `alice.pfx.8417305.bak`. That file
     * is a **complete, openable copy of the account's RSA identity**, it lives in `keystore/<user>/`,
     * and `keystore/<user>/` is exactly what a keystore sync bundles. `DirectoryBundler`'s exclusion
     * set is exact basenames, so a random infix matched nothing and one interrupted commit put the
     * device's private identity key on the wire. Only a fixed name can be excluded, so the name is
     * fixed — and this asserts the writer really uses it, because the exclusion on the other side is
     * spelled out in terms of this constant.
     */
    @Test
    fun `the identity store backup has the one name the sync exclusion can match`() {
        assertEquals("identity.pfx.bak", KeystoreClient.identityStoreBackupName(FILE_NAME))
        assertEquals(".bak", KeystoreClient.IDENTITY_STORE_BACKUP_SUFFIX)
    }

    /**
     * The lock file is the third and last thing a commit can leave in `keystore/<user>/`, and it is
     * left there on purpose — a lock file unlinked while another process holds it open leaves the two
     * of them locking different inodes, which is no exclusion at all. Permanent debris in a directory
     * a keystore sync bundles needs a name `DirectoryBundler.syncExclusions` can match, and that set
     * is exact basenames.
     */
    @Test
    fun `the identity store lock has the one name the sync exclusion can match`() {
        assertEquals("identity.pfx.lock", KeystoreClient.identityStoreLockName(FILE_NAME))
        assertEquals(".lock", KeystoreClient.IDENTITY_STORE_LOCK_SUFFIX)
    }

    /**
     * A successful commit leaves the directory holding the store and nothing else.
     *
     * The backup exists only for the width of the swap. Leaving one behind would mean every account
     * permanently carries a second copy of its private key next to the first — and, until the
     * exclusion landed, syncing it.
     */
    @Test
    fun `a successful commit leaves no backup and no temp file behind`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        identityStore().writeBytes(bouncyCastleDefaultStore(KeyPairGenerator.getInstance("RSA").generateKeyPair()))

        assertIs<Outcome.Success<Unit>>(client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD))

        assertEquals(storeAndLock, directory.list()?.sorted(), "the commit must clean up after itself")
    }

    /**
     * A stale backup from some earlier interrupted commit must not survive the next successful one.
     *
     * With a deterministic name this is well defined rather than accidental: the fresh backup is
     * written over the stale one and then deleted with it. The alternative — the old random names —
     * accumulated a pile of openable private keys in the sync directory, one per interrupted commit,
     * with nothing able to distinguish or remove them.
     */
    @Test
    fun `a fresh commit replaces a stale backup and does not keep it`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        identityStore().writeBytes(bouncyCastleDefaultStore(KeyPairGenerator.getInstance("RSA").generateKeyPair()))
        backupFile().writeText("debris from an interrupted commit two releases ago")

        assertIs<Outcome.Success<Unit>>(client.reencodeIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD))

        assertFalse(backupFile().exists(), "the stale backup must be gone, not shipped and not kept")
        assertEquals(storeAndLock, directory.list()?.sorted())
        assertEquals(LowPbePkcs12Writer.ITERATIONS, profileOf(identityStore().readBytes()).keyIterations)
    }

    /**
     * The dual failure, and the recovery that makes it survivable.
     *
     * On a filesystem that cannot promise an atomic move, `DurableFiles.replace` degrades to a plain
     * replacing move — a copy — so a failure part way through can leave a truncated `.pfx`. The commit
     * immediately puts the backup back; if *that* also fails, it deliberately strands the backup and
     * returns the error, because a `.bak` beside the store can be recovered and a truncated `.pfx`
     * cannot be recovered at all.
     *
     * The aftermath is constructed rather than provoked. A dual move failure needs a filesystem this
     * test host does not have, and there is no way to make a thread stop between the two `Files.move`
     * calls that does not also skip the cleanup the failure is supposed to skip — the same reason
     * `KeyringBootstrapTest` builds interrupted password changes by hand. What is constructed is
     * exactly what the code writes: the backup is a byte copy of the live store (that is all
     * `copyDurably` does), and the live store is truncated. The *recovery* is entirely real.
     */
    @Test
    fun `a stranded backup is restored on the next open and the store works again`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val identity = assertNotNull(
            client.unwrapKey(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow(), ALIAS, PASSWORD.toCharArray()),
        ).encoded
        strandBackupOverTruncatedStore()
        assertNull(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrNull(), "precondition: the store is unusable")

        assertTrue(restore(PASSWORD))

        assertContentEquals(
            identity,
            assertNotNull(
                client.unwrapKey(client.getKeyStoreInfo(descriptor(PASSWORD)).getOrThrow(), ALIAS, PASSWORD.toCharArray()),
            ).encoded,
            "the recovered store must hold the same RSA identity, not a new one",
        )
        assertFalse(backupFile().exists(), "a consumed backup is no longer the last copy and must not linger")
        assertEquals(storeAndLock, directory.list()?.sorted())
    }

    /**
     * **The most dangerous thing this could do is fire when it should not.**
     *
     * A store that does not open under the password being tried is the ordinary answer during login —
     * `resolveIdentityStorePassword` asks with the derived password and then the login password, and
     * one of those is expected to fail. If "does not open" were the trigger, a stale backup left by an
     * older commit under an older password would be restored straight over a perfectly good current
     * store, destroying the live identity to recover a dead one. So the trigger is that the live store
     * is not a readable PKCS#12 *at all*, which needs no password to establish.
     */
    @Test
    fun `a stale backup is not restored over a live store that opens`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val live = identityStore().readBytes()
        // A complete, openable store — under a password this account has moved off.
        writeBackup(freshStoreSealedWith(SECOND_PASSWORD))

        assertFalse(restore(PASSWORD), "the live store is intact; there is nothing to recover")
        assertFalse(
            restore(SECOND_PASSWORD),
            "and it must not be restorable by holding the backup's own password either",
        )

        assertContentEquals(live, identityStore().readBytes(), "the live store must be untouched")
        assertTrue(backupFile().exists(), "and a backup that was never consumed must not be deleted")
    }

    /**
     * A backup that does not open under the password in hand is not a recovery, and it is not debris
     * either — it is the only remaining evidence of whatever went wrong. It stays on disk.
     */
    @Test
    fun `a backup that does not verify is neither restored nor deleted`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val backup = freshStoreSealedWith(SECOND_PASSWORD)
        strandBackupOverTruncatedStore()
        writeBackup(backup)
        val truncated = identityStore().readBytes()

        assertFalse(
            restore(PASSWORD),
            "a backup this password cannot open proves nothing and must not be published",
        )

        assertContentEquals(backup, backupFile().readBytes(), "never delete a backup that did not verify")
        assertContentEquals(truncated, identityStore().readBytes())
    }

    @Test
    fun `there is nothing to restore when no backup exists`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        identityStore().writeBytes(ByteArray(16))

        assertFalse(restore(PASSWORD))
    }

    /**
     * A backup holding no private key is not an identity store, whatever else it is. Restoring it
     * would replace a damaged store with a useless one and delete the evidence on the way past.
     */
    @Test
    fun `a backup with no private key is refused`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val certificatesOnly = KeyStore.getInstance("PKCS12", "BC").apply {
            load(null, PASSWORD.toCharArray())
            setCertificateEntry(TRUSTED_ALIAS, trustedCertificate())
        }.let { store ->
            ByteArrayOutputStream().use { output ->
                store.store(output, PASSWORD.toCharArray())
                output.toByteArray()
            }
        }
        strandBackupOverTruncatedStore()
        writeBackup(certificatesOnly)

        assertFalse(restore(PASSWORD))
        assertTrue(backupFile().exists())
    }

    /**
     * A backup holding a private key under *some other* alias is not this account's identity.
     *
     * The recovery used to verify "at least one private-key alias unwraps", while the only caller —
     * `JvmKeystoreLifecycle.canOpenKeystore` — goes on to demand `passmanMain` specifically. A backup
     * carrying only `somethingElse` therefore passed here, was published over the live store, and was
     * **deleted** as consumed; the caller's probe then failed and the one artefact anybody could have
     * recovered from was gone. The alias the recovery proves and the alias the caller requires have to
     * be the same alias, so it is now a parameter and the caller passes the constant it checks.
     *
     * Weaken the check back to "any private-key alias" and this fails three ways: the call returns
     * true, the truncated store is replaced, and the backup is deleted.
     */
    @Test
    fun `a backup whose key is under another alias is refused and kept`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val foreign = freshStoreSealedWith(PASSWORD, alias = "somethingElse")
        strandBackupOverTruncatedStore()
        writeBackup(foreign)
        val truncated = identityStore().readBytes()

        val declined = withCapturedLogs { assertFalse(restore(PASSWORD), "this backup cannot satisfy the caller's probe") }

        assertContentEquals(foreign, backupFile().readBytes(), "the only recovery artefact must survive")
        assertContentEquals(truncated, identityStore().readBytes(), "and the live store must be left as it was")
        val reason = assertNotNull(
            declined.firstOrNull { "recovery declined" in it },
            "the refusal must say why; logged instead: $declined",
        )
        assertTrue(ALIAS in reason, "the reason must name the alias that was required: $reason")
        // Lowercased on the way in: SUN lowercases every alias it loads, so this is the name the
        // store reported rather than the name the fixture wrote.
        assertTrue(
            "somethingelse" in reason.lowercase(),
            "and the alias it actually found, so the file can be identified: $reason",
        )
    }

    // ------------------------------------------------------------------- the commit/recovery race

    /**
     * **The recovery must not resurrect a store that a commit has just replaced.**
     *
     * The two writers of the identity store disagree by construction: a recovery decides "the live
     * store is unreadable, publish the backup", a commit decides "here is a new store, and the backup
     * is now debris". Interleaved, the recovery's decision goes stale between reading and publishing —
     * login B sees the live file mid-`DurableFiles.replace` (the cross-device fallback is a copy, so
     * there is a window where it is short), login A's commit finishes and deletes the backup, and B
     * then publishes what it read. The store is back to its pre-commit contents and the backup is
     * gone; when A's commit was the login-password→derived-password migration, that migration reported
     * success and was then silently reverted, with nothing left to recover from.
     *
     * Ordering the two is half the fix and the re-check is the other half, because the lock can only
     * order them — it cannot make B's earlier reading true again. So this drives the exact interleaving:
     * the recovery is started while the lock is held, and by the time it is let through, the live store
     * is a different, valid store. It must notice and decline.
     *
     * The handshake is a thread state rather than a sleep: `TIMED_WAITING` is reachable on this path
     * only from the lock loop's `Thread.sleep`, so observing it proves the recovery has already read
     * the truncated store and is now waiting — which is precisely the state the race needs.
     *
     * Delete the re-check and this fails on both of its assertions: the winner's store is overwritten
     * with the stale backup, and the backup is deleted.
     */
    @Test
    fun `a recovery that loses the race to a commit leaves the winner's store alone`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        strandBackupOverTruncatedStore()
        val backupBytes = backupFile().readBytes()
        // What the winning commit publishes: a different store, sealed under the password the
        // migration moved the account onto. The recovery still holds the old one, which is the case
        // that matters — its backup verifies, so nothing but the re-check stops it.
        val winner = freshStoreSealedWith(SECOND_PASSWORD)

        val restored = AtomicReference<Boolean>()
        val logs = withCapturedLogs {
            lockChannel().use { channel ->
                val held = channel.lock()
                val recovery = Thread { restored.set(restore(PASSWORD)) }.apply { start() }
                try {
                    awaitLockRetry(recovery)
                    identityStore().writeBytes(winner)
                } finally {
                    held.release()
                }
                recovery.join(TimeUnit.SECONDS.toMillis(30))
                assertFalse(recovery.isAlive, "the recovery must finish once the lock is released")
            }
        }

        assertEquals(false, restored.get(), "the store is readable again; there is nothing to recover")
        assertContentEquals(winner, identityStore().readBytes(), "the commit's store must not be reverted")
        assertContentEquals(backupBytes, backupFile().readBytes(), "and an unconsumed backup must be byte-identical")
        // Pins the *reason*. Every assertion above also holds if the recovery merely gave up on the
        // lock, which would leave this test passing while covering nothing; this is the one line only
        // the re-check produces.
        assertTrue(
            logs.any { "became readable" in it },
            "the recovery must decline because it re-checked the live store; logged instead: $logs",
        )
    }

    /**
     * The other half of the bounded loop: a holder that never releases — a second desktop instance at
     * a breakpoint, a stale lock on a network mount — must not hang a login. The blocking
     * `FileChannel.lock()` is uninterruptible and unbounded; the loop gives up after its bound and
     * declines, leaving both files exactly as it found them and saying which lock it waited on.
     */
    @Test
    fun `a recovery gives up on a lock that is never released instead of hanging`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        strandBackupOverTruncatedStore()
        val backupBytes = backupFile().readBytes()
        val truncated = identityStore().readBytes()

        lockChannel().use { channel ->
            val held = channel.lock()
            try {
                val started = System.nanoTime()
                val declined = withCapturedLogs { assertFalse(restore(PASSWORD), "a contended lock is not a recovery") }
                val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

                assertTrue(
                    elapsedMs >= (IDENTITY_STORE_LOCK_ATTEMPTS - 1) * IDENTITY_STORE_LOCK_RETRY_DELAY_MS,
                    "it must exhaust the bounded wait (took ${elapsedMs}ms) rather than degrade immediately",
                )
                assertTrue(
                    declined.any { "recovery declined" in it && KeystoreClient.identityStoreLockName(FILE_NAME) in it },
                    "giving up must name the lock it waited on; logged instead: $declined",
                )
            } finally {
                held.release()
            }
        }

        assertContentEquals(backupBytes, backupFile().readBytes())
        assertContentEquals(truncated, identityStore().readBytes())
    }

    /**
     * The commit side of the same lock, which is what makes it mutual exclusion rather than a lock the
     * recovery takes alone. A commit that cannot get it fails cleanly — an `Outcome.Error` naming the
     * lock, no store touched, no backup left behind — instead of blocking a login forever.
     */
    @Test
    fun `a commit gives up on a lock that is never released instead of hanging`() {
        assertIs<Outcome.Success<Unit>>(createIdentityStore())
        val live = identityStore().readBytes()

        val outcome = lockChannel().use { channel ->
            val held = channel.lock()
            try {
                client.changeIdentityKeyStorePassword(directory.absolutePath, FILE_NAME, PASSWORD, SECOND_STORE_PASSWORD)
            } finally {
                held.release()
            }
        }

        val error = assertIs<Outcome.Error>(outcome)
        assertTrue(
            KeystoreClient.identityStoreLockName(FILE_NAME) in error.message,
            "the failure must name the lock it waited on: ${error.message}",
        )
        assertContentEquals(live, identityStore().readBytes(), "a commit that never ran must not have written")
        assertFalse(backupFile().exists(), "nor left a copy of the identity behind")
    }

    // ------------------------------------------------------------------- the fence

    /**
     * The leak-prevention negative.
     *
     * A keystore created through the tools UI is sealed with whatever password the user typed, so its
     * iteration count is load-bearing in a way the identity store's is not. If this ever starts
     * reporting [LowPbePkcs12Writer.ITERATIONS], somebody has routed the tools path through the
     * identity writer and turned every tool keystore's password into a cheap guessing target.
     */
    @Test
    fun `the keystore tools path keeps the provider's own strong parameters`() {
        val toolsPassword = "hunter2"
        val keystore = client.createKeyStore(KeyStoreType.PKCS12, directory.absolutePath, "tools.p12", toolsPassword).getOrThrow()
        check(client.addKeystoreKey(keystore, "toolKey", toolsPassword, KeystoreKeyAlgorithm.RSA).getOrThrow())

        val profile = profileOf(File(directory, "tools.p12").readBytes())

        // Measured on JDK 17 / BC 1.85: PBES2-AES256 at 10,000 for the key, pbeWithSHAAnd40BitRC2_CBC
        // at 600,000 for the certificates, SHA-1 MAC at 1,200,000. The exact numbers are the
        // providers' business and move between releases; that none of them is a token count is not.
        listOf(profile.keyIterations, profile.certificateIterations, profile.macIterations).forEach { iterations ->
            assertTrue(
                iterations >= 10_000,
                "a tool keystore is sealed with a human password and must keep a real work factor, was $iterations",
            )
        }
    }

    // ------------------------------------------------------------------- fixtures

    private fun createIdentityStore(): Outcome<Unit> =
        client.createIdentityKeyStore(directory.absolutePath, FILE_NAME, STORE_PASSWORD, ALIAS)

    private fun identityStore(): File = File(directory, FILE_NAME)

    private fun backupFile(): File = File(directory, KeystoreClient.identityStoreBackupName(FILE_NAME))

    private fun writeBackup(bytes: ByteArray) = backupFile().writeBytes(bytes)

    private fun descriptor(password: String) = Keystore(directory.absolutePath, FILE_NAME, password)

    /** The recovery, always asked for the alias the production caller goes on to probe for. */
    private fun restore(password: String): Boolean =
        client.restoreIdentityKeyStoreFromBackup(directory.absolutePath, FILE_NAME, password, ALIAS)

    /**
     * What a directory holds once a commit has run: the store, and the lock file the commit created
     * and deliberately did not delete (see `KeystoreClient.IDENTITY_STORE_LOCK_SUFFIX`). Anything else
     * is debris, and `DirectoryBundler.syncExclusions` has to know about all of it.
     */
    private val storeAndLock: List<String>
        get() = listOf(FILE_NAME, KeystoreClient.identityStoreLockName(FILE_NAME)).sorted()

    /**
     * A second channel onto the same lock file, standing in for the other process. In this JVM a
     * lock held here surfaces to the production loop as `OverlappingFileLockException`, which it
     * treats exactly as it treats another process's lock: wait and ask again.
     */
    private fun lockChannel(): FileChannel = FileChannel.open(
        File(directory, KeystoreClient.identityStoreLockName(FILE_NAME)).toPath(),
        StandardOpenOption.CREATE,
        StandardOpenOption.WRITE,
    )

    /**
     * Block until [thread] is provably inside the lock's bounded retry loop.
     *
     * `TIMED_WAITING` is reachable on this path only from that loop's `Thread.sleep` — everything
     * before it is a `stat`, a `FileChannel.open` and a `tryLock` — so this is a real handshake rather
     * than a guess at how long a thread takes to start: when it returns, the recovery has already read
     * the live store and found it damaged, and is waiting for the lock.
     */
    private fun awaitLockRetry(thread: Thread) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            if (thread.state == Thread.State.TIMED_WAITING) return
            assertNotEquals(
                Thread.State.TERMINATED,
                thread.state,
                "the recovery returned instead of waiting for the contended lock",
            )
            Thread.sleep(1)
        }
        fail("the recovery never reached the lock's bounded retry loop")
    }

    /** Run [block] with a logger attached, and hand back every message it produced, any thread. */
    private fun withCapturedLogs(block: () -> Unit): List<String> {
        val capture = CapturingLogger()
        KLogger.registerLoggers(capture)
        try {
            block()
        } finally {
            KLogger.unregisterLoggers(capture)
        }
        return capture.messages()
    }

    private class CapturingLogger : Logger {
        private val lines = mutableListOf<String>()

        override fun log(
            priority: Logger.Priority,
            explicitTag: String?,
            inferredTag: String,
            message: String?,
            throwable: Throwable?,
            properties: Map<String, String>?,
        ) {
            if (message != null) synchronized(lines) { lines += message }
        }

        fun messages(): List<String> = synchronized(lines) { lines.toList() }
    }

    /**
     * The exact on-disk state a dual failure leaves: a byte copy of the live store at the backup path
     * — which is all `copyDurably` writes — and a live store truncated by a replace that got part way
     * through a cross-device copy.
     */
    private fun strandBackupOverTruncatedStore() {
        writeBackup(identityStore().readBytes())
        RandomAccessFile(identityStore(), "rw").use { it.setLength(it.length() / 3) }
    }

    /**
     * A complete, openable identity store sealed with [password] under [alias], built by the
     * production writer. Built in a directory of its own so it never meets this test's lock file.
     */
    private fun freshStoreSealedWith(password: String, alias: String = ALIAS): ByteArray {
        val other = Files.createTempDirectory("low-pbe-other").toFile()
        try {
            assertIs<Outcome.Success<Unit>>(
                client.createIdentityKeyStore(
                    other.absolutePath,
                    FILE_NAME,
                    IdentityStorePassword.unsafeNotFromKeyring(password),
                    alias,
                ),
            )
            return File(other, FILE_NAME).readBytes()
        } finally {
            other.deleteRecursively()
        }
    }

    /**
     * Cheap PBES2 bags under BouncyCastle's own default file MAC: SHA-1 at 1,200,000.
     *
     * Built with the same `PKCS12PfxPduBuilder` the production writer uses, changing only the MAC, so
     * the fixture differs from a good store in exactly the one dimension under test.
     */
    private fun lowBagsExpensiveMacStore(keyPair: KeyPair): ByteArray {
        val provider = BouncyCastleProvider()
        fun encryptor() = JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
            .setProvider(provider)
            .setIterationCount(LowPbePkcs12Writer.ITERATIONS)
            .setPRF(AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
            .build(PASSWORD.toCharArray())

        return PKCS12PfxPduBuilder().apply {
            addData(
                JcaPKCS12SafeBagBuilder(keyPair.private, encryptor())
                    .apply { addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(ALIAS)) }
                    .build(),
            )
            addEncryptedData(encryptor(), arrayOf(JcaPKCS12SafeBagBuilder(trustedCertificate()).build()))
        }.build(
            // No digest argument: BouncyCastle's default here is SHA-1, which is what it really writes.
            JcePKCS12MacCalculatorBuilder().setProvider(provider).setIterationCount(1_200_000),
            PASSWORD.toCharArray(),
        ).encoded
    }

    /**
     * What stock SUN produces: 10,000 for the key, the certificates and the MAC on JDK 17.
     *
     * BouncyCastle has to be demoted for the write. With it at provider position 1 its PBE wins the
     * `Cipher.getInstance` inside SUN's `store()` and the file comes out with BouncyCastle's
     * parameters instead — the same provider-ordering hazard the production loader demotes for, and
     * here it would quietly turn this fixture into a copy of the previous one.
     */
    private fun sunDefaultStore(keyPair: KeyPair): ByteArray = withBouncyCastleDemoted {
        val keyStore = KeyStore.getInstance("PKCS12", "SUN").apply {
            load(null, PASSWORD.toCharArray())
            setKeyEntry(ALIAS, keyPair.private, PASSWORD.toCharArray(), arrayOf(trustedCertificate()))
        }
        ByteArrayOutputStream().use { output ->
            keyStore.store(output, PASSWORD.toCharArray())
            output.toByteArray()
        }
    }

    /** What BouncyCastle's JCA writer produces unprompted: 3DES / RC2 at 600,000, SHA-1 MAC at 1,200,000. */
    private fun bouncyCastleDefaultStore(keyPair: java.security.KeyPair): ByteArray =
        KeyStore.getInstance("PKCS12", "BC").apply {
            load(null, PASSWORD.toCharArray())
            setKeyEntry(ALIAS, keyPair.private, PASSWORD.toCharArray(), arrayOf(trustedCertificate()))
        }.let { keyStore ->
            ByteArrayOutputStream().use { output ->
                keyStore.store(output, PASSWORD.toCharArray())
                output.toByteArray()
            }
        }

    private fun load(encoded: ByteArray, provider: String): KeyStore =
        KeyStore.getInstance("PKCS12", provider).apply { load(ByteArrayInputStream(encoded), PASSWORD.toCharArray()) }

    private fun <T> withBouncyCastleDemoted(block: () -> T): T {
        val present = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null
        if (present) Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        try {
            return block()
        } finally {
            if (present && Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
            }
        }
    }

    private fun trustedCertificate(): X509Certificate {
        val cacerts = KeyStore.getInstance("JKS", "SUN").apply {
            FileInputStream("${System.getProperty("java.home")}/lib/security/cacerts").use {
                load(it, "changeit".toCharArray())
            }
        }
        return CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(cacerts.getCertificate(cacerts.aliases().nextElement()).encoded),
        ) as X509Certificate
    }

    // ------------------------------------------------------------------- ASN.1

    private class Profile(
        val keyAlgorithm: ASN1ObjectIdentifier,
        val keyIterations: Int,
        val keyPrf: ASN1ObjectIdentifier?,
        val keyEncryptionScheme: ASN1ObjectIdentifier?,
        val certificateAlgorithm: ASN1ObjectIdentifier,
        val certificateIterations: Int,
        val macDigest: ASN1ObjectIdentifier,
        val macIterations: Int,
    )

    private fun profileOf(encoded: ByteArray): Profile {
        val pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(encoded))
        val authenticatedSafe = AuthenticatedSafe.getInstance(
            ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(pfx.authSafe.content).octets),
        )
        val keyAlgorithm = authenticatedSafe.contentInfo
            .filter { it.contentType == PKCSObjectIdentifiers.data }
            .flatMap { contentInfo ->
                val bags = ASN1Sequence.getInstance(ASN1OctetString.getInstance(contentInfo.content).octets)
                (0 until bags.size()).map { SafeBag.getInstance(bags.getObjectAt(it)) }
            }
            .first { it.bagId == PKCSObjectIdentifiers.pkcs8ShroudedKeyBag }
            .let { EncryptedPrivateKeyInfo.getInstance(it.bagValue).encryptionAlgorithm }
        val certificateAlgorithm = authenticatedSafe.contentInfo
            .first { it.contentType == PKCSObjectIdentifiers.encryptedData }
            .let { EncryptedData.getInstance(it.content).encryptionAlgorithm }
        val mac = requireNotNull(pfx.macData)
        val pbes2 = pbes2Of(keyAlgorithm)
        return Profile(
            keyAlgorithm = keyAlgorithm.algorithm,
            keyIterations = iterationsOf(keyAlgorithm),
            keyPrf = pbes2?.first,
            keyEncryptionScheme = pbes2?.second,
            certificateAlgorithm = certificateAlgorithm.algorithm,
            certificateIterations = iterationsOf(certificateAlgorithm),
            macDigest = mac.mac.algorithmId.algorithm,
            macIterations = mac.iterationCount.intValueExact(),
        )
    }

    private fun pbes2Of(algorithm: AlgorithmIdentifier): Pair<ASN1ObjectIdentifier, ASN1ObjectIdentifier>? {
        if (algorithm.algorithm != PKCSObjectIdentifiers.id_PBES2) return null
        val parameters = PBES2Parameters.getInstance(algorithm.parameters)
        return PBKDF2Params.getInstance(parameters.keyDerivationFunc.parameters).prf.algorithm to
            parameters.encryptionScheme.algorithm
    }

    private fun iterationsOf(algorithm: AlgorithmIdentifier): Int = when (algorithm.algorithm) {
        PKCSObjectIdentifiers.id_PBES2 -> PBKDF2Params.getInstance(
            PBES2Parameters.getInstance(algorithm.parameters).keyDerivationFunc.parameters,
        ).iterationCount.intValueExact()

        else -> PKCS12PBEParams.getInstance(algorithm.parameters).iterations.intValueExact()
    }

    private companion object {
        const val FILE_NAME = "identity.pfx"
        const val ALIAS = "passmanMain"
        const val TRUSTED_ALIAS = "trustedRoot"

        /** Stands in for the keyring-derived password: 256 bits, base64, nothing to guess. */
        const val PASSWORD = "Zm9yLXRlc3RzLW9ubHktMzItYnl0ZXMtb2YtZW50cm9weQ=="
        const val SECOND_PASSWORD = "YS1zZWNvbmQtMzItYnl0ZS1kZXJpdmVkLXN0b3JlLXB3ZA=="

        /**
         * The capability tokens for the two passwords above.
         *
         * [IdentityStorePassword.unsafeNotFromKeyring] is the only way to make one without a live
         * keyring, and it is named to be conspicuous for exactly that reason: in production the sole
         * source is `VaultCipher.identityStorePassword`, which is the derivation. A test does not have
         * a device master key to derive from, so it says so out loud instead of pretending.
         */
        val STORE_PASSWORD = IdentityStorePassword.unsafeNotFromKeyring(PASSWORD)
        val SECOND_STORE_PASSWORD = IdentityStorePassword.unsafeNotFromKeyring(SECOND_PASSWORD)

        val ALL_OWNER_PERMISSIONS = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
    }
}
