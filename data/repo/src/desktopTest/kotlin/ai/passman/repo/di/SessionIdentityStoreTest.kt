package ai.passman.repo.di

import ai.passman.crypto.CryptoKey
import ai.passman.keystore.JvmKeyStoreClient
import ai.passman.keystore.KeystoreClient
import ai.passman.keystore.model.Keystore
import ai.passman.repo.Platform
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import java.io.File
import java.nio.file.Files
import java.security.Key
import java.security.KeyStore
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.parameter.parametersOf
import org.koin.core.qualifier.named
import org.koin.core.scope.Scope
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * One login, one PKCS#12 open.
 *
 * Opening the identity store runs PKCS#12's PBE over the whole file — measured in seconds on a
 * phone — and login resolves both RSA key handles, so the two of them used to cost two full opens.
 * The session-scoped [SESSION_IDENTITY_STORE] definition is what collapses that to one, and the
 * only way to see it is to count the loads: every key involved still comes out correct either way,
 * which is exactly why an assertion on the keys alone cannot protect this.
 *
 * The other half is that the sharing is per *session scope* and not process-wide. Logout closes the
 * scope; if the open store outlived it, a later login — different account, different password —
 * could be handed the previous one's store and its keys. So the second scope here is a different
 * account, and it must get its own open and its own keys.
 *
 * Everything below the seams is real: a real `JvmKeyStoreClient` writing real PKCS#12 files and the
 * real `toolsModule` graph. The only decoration is a counter around `getKeyStoreInfo`.
 */
class SessionIdentityStoreTest {

    private lateinit var root: File
    private lateinit var counting: CountingKeystoreClient
    private lateinit var aliceCertificateKey: Key
    private lateinit var bobCertificateKey: Key
    private val openedScopes = mutableListOf<Scope>()

    private val alice = "alice"
    private val alicePassword = "alice-derived-identity-store-password"
    private val bob = "bob"
    private val bobPassword = "bob-derived-identity-store-password"

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("session-identity-store").toFile()
        // The fixture writes through a bare client, so the counter starts at zero for the test body.
        val fixtureClient = JvmKeyStoreClient()
        aliceCertificateKey = createAccount(fixtureClient, alice, alicePassword)
        bobCertificateKey = createAccount(fixtureClient, bob, bobPassword)
        assertFalse(
            aliceCertificateKey.encoded.contentEquals(bobCertificateKey.encoded),
            "fixture precondition: the two accounts must hold different identity keys",
        )

        counting = CountingKeystoreClient(JvmKeyStoreClient())
        startKoin {
            modules(
                toolsModule,
                module {
                    single<Platform> { FakePlatform(root) }
                    single<KeystoreClient> { counting }
                },
            )
        }
    }

    @AfterTest
    fun tearDown() {
        openedScopes.forEach { it.close() }
        stopKoin()
        root.deleteRecursively()
    }

    @Test
    fun `both session key handles come out of a single identity store open`() {
        val scope = sessionScope("session-one")

        val publicHandle = scope.get<CryptoKey>(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { parametersOf(alice, alicePassword) }
        val privateHandle = scope.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { parametersOf(alice, alicePassword) }

        assertEquals(
            1,
            counting.getKeyStoreInfoCalls,
            "resolving both key handles must open the .pfx once, not once per key",
        )
        assertContentEquals(
            aliceCertificateKey.encoded,
            publicHandle.encoded,
            "the public handle must be the certificate's key from the account's own store",
        )
        // Not merely non-null: the private handle has to be the counterpart of that public key, which
        // it is only if `unwrapKey` was given the store password it is actually sealed with.
        assertRoundTrips(publicHandle, privateHandle)
    }

    @Test
    fun `the raw key qualifiers still resolve without parameters once the session is warm`() {
        val scope = sessionScope("session-one")
        scope.get<CryptoKey>(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { parametersOf(alice, alicePassword) }
        scope.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { parametersOf(alice, alicePassword) }

        // SyncTlsProvider, FileTransferRepository and JvmFingerprintService all resolve these by
        // qualifier alone on the scope login warmed, with no parameters to pass.
        val privateKey = assertNotNull(scope.getOrNull<Key>(named(PRIVATE_DECRYPTION_KEY)))
        val publicKey = assertNotNull(scope.getOrNull<Key>(named(PUBLIC_ENCRYPTION_KEY)))

        assertContentEquals(aliceCertificateKey.encoded, publicKey.encoded)
        assertEquals("RSA", privateKey.algorithm)
        assertEquals(1, counting.getKeyStoreInfoCalls, "a parameter-less lookup must not reopen the store")
    }

    @Test
    fun `a second session scope opens its own store rather than inheriting the first one's`() {
        val first = sessionScope("session-one")
        first.get<CryptoKey>(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { parametersOf(alice, alicePassword) }
        first.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { parametersOf(alice, alicePassword) }
        assertEquals(1, counting.getKeyStoreInfoCalls)

        val second = sessionScope("session-two")
        val publicHandle = second.get<CryptoKey>(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { parametersOf(bob, bobPassword) }
        val privateHandle = second.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { parametersOf(bob, bobPassword) }

        assertEquals(
            2,
            counting.getKeyStoreInfoCalls,
            "the open store must be cached per session scope; a process-wide cache would survive logout",
        )
        assertContentEquals(
            bobCertificateKey.encoded,
            publicHandle.encoded,
            "the second session must get its own account's key, not the one the first session cached",
        )
        assertRoundTrips(publicHandle, privateHandle)
    }

    // ----------------------------------------------------------------- setup

    /** An account laid out exactly where `keystoreDescriptor` looks for one, with the frozen alias. */
    private fun createAccount(client: JvmKeyStoreClient, username: String, storePassword: String): Key {
        val directory = File(root, "keystore/$username").apply { mkdirs() }
        val descriptor: Keystore = client.createKeyStore(
            KeyStoreType.PKCS12,
            directory.absolutePath,
            "$username.pfx",
            storePassword,
        ).getOrThrow()
        check(client.addKeystoreKey(descriptor, IDENTITY_ALIAS, storePassword, KeystoreKeyAlgorithm.RSA).getOrThrow()) {
            "could not write the identity key for $username"
        }
        val store: KeyStore = client.getKeyStoreInfo(descriptor).getOrThrow()
        return checkNotNull(store.getCertificate(IDENTITY_ALIAS)) { "no certificate under $IDENTITY_ALIAS" }.publicKey
    }

    private fun sessionScope(id: String): Scope =
        KoinPlatform.getKoin().createScope(id, named("sessionScope")).also { openedScopes += it }

    /** Proves the two handles are a real RSA pair from the same store, not two unrelated keys. */
    private fun assertRoundTrips(publicHandle: CryptoKey, privateHandle: CryptoKey) {
        val aad = "session-identity-store-test"
        val cipher = JvmKeyStoreClient()
        val encrypted = assertIs<Outcome.Success<EncryptedData>>(
            cipher.encryptData(publicHandle.key, PLAINTEXT, aad.encodeToByteArray()),
        ).value
        assertEquals(
            PLAINTEXT,
            assertIs<Outcome.Success<String>>(cipher.decryptData(privateHandle.key, encrypted.ciphertextOrPath, aad)).value,
        )
    }

    private class FakePlatform(private val localPath: File) : Platform() {
        override fun getLocalPath(): String = localPath.absolutePath
    }

    /**
     * Real behaviour, plus the one number this file exists to assert on: how many times the identity
     * store was actually loaded off disk.
     */
    private class CountingKeystoreClient(private val delegate: KeystoreClient) : KeystoreClient by delegate {
        var getKeyStoreInfoCalls = 0
            private set

        override fun getKeyStoreInfo(keystore: Keystore): Result<KeyStore?> {
            getKeyStoreInfoCalls++
            return delegate.getKeyStoreInfo(keystore)
        }
    }

    private companion object {
        /** What `ToolsModule` resolves, and what is on disk. Not a knob. */
        const val IDENTITY_ALIAS = "passmanMain"
        const val PLAINTEXT = "plain text"
    }
}
