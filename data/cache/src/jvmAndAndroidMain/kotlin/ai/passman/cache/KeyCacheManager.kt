package ai.passman.cache

import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import java.security.Key
import java.security.KeyStore

/** Caches only metadata and a public key; private and secret keys are never retained. */
data class CachedKeystoreKey(
    val publicKey: Key?,
    val algorithm: KeystoreKeyAlgorithm,
)

data class KeyCache(val keystorePath: String, val keystoreName: String, val key: CachedKeystoreKey)

class KeyCacheManager {
    private val cache = mutableMapOf<String, KeyCache>()

    var keyStore: KeyStore? = null

    fun getKey(alias: String, keystoreName: String, keystorePath: String): CachedKeystoreKey? {
        val cacheEntry = cache[generateCacheKey(keystorePath, keystoreName, alias)]

        return cacheEntry?.key
    }

    fun cacheKey(alias: String, key: CachedKeystoreKey, keystoreName: String, keystorePath: String) {
        cache[generateCacheKey(keystorePath, keystoreName, alias)] = KeyCache(keystorePath, keystoreName, key)
    }

    fun clear() {
        cache.clear()
        keyStore = null
    }

    private fun generateCacheKey(keystorePath: String, keystoreName: String, alias: String): String {
        return "$keystoreName|$keystorePath|$alias"
    }
}
