package ai.passman.repo.di

import ai.passman.cache.KeyCacheManager
import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.keystore.KeystoreClient
import ai.passman.keystore.model.Keystore
import ai.passman.repo.Platform
import java.io.File
import java.security.Key
import java.security.KeyStore
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.koin.core.parameter.parametersOf
import org.koin.core.qualifier.named
import org.koin.core.scope.Scope
import org.koin.dsl.module
import org.koin.dsl.onClose

const val PUBLIC_ENCRYPTION_KEY = "encryptionKey"
const val PRIVATE_DECRYPTION_KEY = "decryptionKey"

/**
 * The account's PKCS#12 identity store, opened once per session scope.
 *
 * Lives here rather than in `Qualifiers.kt` because what it names is a `java.security.KeyStore`, so
 * the definition it belongs to cannot leave `jvmAndAndroidMain`.
 */
const val SESSION_IDENTITY_STORE = "sessionIdentityStore"

const val KEYSTORE_CACHE = "keystoreCache"

/**
 * The alias every account's identity key pair is written under. Frozen: it is on disk.
 *
 * Aliased from `data:keystore`, which is where the store is written and where a recovered backup is
 * verified against this same name; a second literal here is a second thing to forget to change.
 */
private const val IDENTITY_KEY_ALIAS = KeystoreClient.IDENTITY_KEY_ALIAS

val toolsModule = module {
    single { BouncyCastleProvider() }
    single<CryptoService> { JvmCryptoService() }
    single<VaultCipher> { PasswordVaultCipher(cryptoService = get()) }

    scope(named("sessionScope")) {
        // The unwrapped device master key for this login, and nothing longer. `onClose` fires when
        // the session scope is closed (logout, or a rolled-back signup) and zeroes the key material,
        // so no caller has to remember to. Nothing else may hold a reference to the key across the
        // scope boundary — it must never reach AppUser, preferences, a log line, or a singleton.
        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() } onClose { it?.destroy() }

        // Opening a PKCS#12 runs its PBE over the whole file — seconds on a phone — and both key
        // definitions below need the same open store. Sharing one `scoped` instance is what makes a
        // login pay that once instead of once per key. Caching is per *session* scope on purpose:
        // logout closes the scope and drops this store along with the keys taken out of it, so a
        // later login under a different password cannot be handed the previous account's store.
        scoped(named(SESSION_IDENTITY_STORE)) { (param1: String, param2: String) ->
            openIdentityStore(client = get(), platform = get(), keystore = param1, password = param2)
        }

        // param2 is the *identity-store* password. Since the device keyring landed that is a
        // 256-bit value derived from the device master key, not the login password — see
        // VaultCipher.identityStorePassword. The parameter shape and the qualifier names are frozen:
        // SyncTlsProvider and JvmFingerprintService resolve these by qualifier.
        scoped(named(PUBLIC_ENCRYPTION_KEY)) { (param1: String, param2: String) ->
            getPublicKey(keyStore = identityStore(param1, param2), alias = IDENTITY_KEY_ALIAS)
        }

        scoped(named(PRIVATE_DECRYPTION_KEY)) { (param1: String, param2: String) ->
            getPrivateKey(
                client = get(),
                keyStore = identityStore(param1, param2),
                alias = IDENTITY_KEY_ALIAS,
                password = param2,
            )
        }

        scoped(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { (param1: String, param2: String) ->
            CryptoKey(get<Key>(named(PUBLIC_ENCRYPTION_KEY)) { parametersOf(param1, param2) })
        }

        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { (param1: String, param2: String) ->
            CryptoKey(get<Key>(named(PRIVATE_DECRYPTION_KEY)) { parametersOf(param1, param2) })
        }
    }

    scope(named("keystoreCacheScope")) {
        scoped(named(KEYSTORE_CACHE)) {
            KeyCacheManager()
        }
    }
}

private fun keystoreDescriptor(platform: Platform, keystore: String, password: String): Keystore? {
    val directory = File("${platform.getLocalPath()}${File.separator}keystore${File.separator}$keystore")
    val file = File(directory, "${keystore}.pfx")
    if (!file.exists()) {
        return null
    }
    return Keystore(path = directory.absolutePath, name = file.name, password = password)
}

/**
 * The identity store this session opened, shared by both key definitions above.
 *
 * A `scoped` definition caches its first instance for the life of the scope and ignores
 * `parametersOf` on every later resolution, so whichever key is resolved first pays for the open and
 * the other one gets the same [KeyStore] back — which is the entire point. Both callers pass the
 * same pair anyway, because both are resolved from one `warmIdentityKeys` call.
 */
private fun Scope.identityStore(keystore: String, password: String): KeyStore =
    get(named(SESSION_IDENTITY_STORE)) { parametersOf(keystore, password) }

// Loading goes through KeystoreClient so the SUN/BouncyCastle provider negotiation matches the
// writer's provider — otherwise a SUN-written .pfx is unreadable by BC and vice versa.
private fun openIdentityStore(client: KeystoreClient, platform: Platform, keystore: String, password: String): KeyStore? {
    val descriptor = keystoreDescriptor(platform, keystore, password) ?: return null
    return client.getKeyStoreInfo(descriptor).getOrNull()
}

// Certificates do not need unwrapKey: only the private-key bag requires provider-specific unwrap.
private fun getPublicKey(keyStore: KeyStore, alias: String): Key? = keyStore.getCertificate(alias)?.publicKey

// [password] is the per-key password, which since 2026-08-06 is the identity-store password rather
// than an empty one. Unwrapping without it is what that fix removed; do not put it back.
private fun getPrivateKey(client: KeystoreClient, keyStore: KeyStore, alias: String, password: String): Key? =
    client.unwrapKey(keyStore, alias, password.toCharArray())
