package ai.passman.platform.prefs

import ai.passman.repo.DesktopProfile
import ai.passman.logging.KLogger
import com.microsoft.credentialstorage.SecretStore
import com.microsoft.credentialstorage.StorageProvider
import com.microsoft.credentialstorage.model.StoredCredential
import com.russhwolf.settings.PreferencesSettings
import com.russhwolf.settings.Settings
import java.io.OutputStream
import java.security.Key
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.prefs.NodeChangeListener
import java.util.prefs.PreferenceChangeEvent
import java.util.prefs.PreferenceChangeListener
import java.util.prefs.Preferences
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.asKotlinRandom

private const val MASTER_KEY_USER = "passman"

class DesktopEncryptionSettingsFactory(
    private val profile: DesktopProfile,
    /**
     * The platform's secure credential store, or `null` where there is none. Injectable so the
     * no-store path can be tested on a machine that has one.
     */
    private val credentialStorage: () -> SecretStore<StoredCredential>? = {
        StorageProvider.getCredentialStorage(true, StorageProvider.SecureOption.REQUIRED)
    },
) : EncryptionSettingsFactory {
    override fun createEncrypted(name: String): Settings {
        val masterKey = loadOrCreateMasterKey()
        // Each named store gets its own child node. Previously `name` was ignored and every
        // store (user_info, user_vault, keystore, pgp_prefs, trusted_devices) shared one node,
        // so `clear()` on any store (e.g. the vault's clearKeys() at logout) wiped the login
        // credentials and trusted-device list too, locking the user out of their own vault.
        val safeName = name.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        val node = Preferences.userRoot().node("${profile.encryptedNodeName}/$safeName")
        migrateLegacyFlatNode(node)
        return PreferencesSettings(EncryptedPreferences(masterKey, node))
    }

    /**
     * One-time migration for installs created before per-store nodes existed. If this store's
     * node is empty but the old shared flat node has data, copy the still-encrypted entries in
     * verbatim. Key names are deterministically encrypted, so lookups keep working; entries that
     * belong to other stores are simply never queried. Idempotent: skipped once the node is populated.
     */
    private fun migrateLegacyFlatNode(node: Preferences) {
        runCatching {
            if (node.keys().isNotEmpty()) return
            val legacyPath = profile.encryptedNodeName
            if (!Preferences.userRoot().nodeExists(legacyPath)) return
            val legacy = Preferences.userRoot().node(legacyPath)
            val legacyKeys = legacy.keys()
            if (legacyKeys.isEmpty()) return
            for (k in legacyKeys) {
                legacy.get(k, null)?.let { node.put(k, it) }
            }
            node.flush()
        }.onFailure { KLogger.e(it) { "DesktopEncryptionSettingsFactory: legacy prefs migration failed" } }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun loadOrCreateMasterKey(): Key {
        // `null` means the system exposes no secure store — a Linux session with no keyring or no
        // D-Bus, typically. There is nowhere safe to keep the key that protects the preferences, so
        // this refuses rather than inventing somewhere; it used to dereference the null and hand the
        // user a NullPointerException out of a password manager.
        val credentialStorage = credentialStorage() ?: error(
            "no secure credential store is available on this system, so the master key protecting " +
                "your encrypted preferences cannot be stored. On Linux this usually means no " +
                "keyring service (gnome-keyring / KWallet via libsecret) is running for this session.",
        )
        val storedMasterKey = credentialStorage.get(profile.masterKeyName)?.password
        return if (storedMasterKey == null) {
            // Explicit 256-bit; the JCE default for "AES" is 128 (Android side already uses 256).
            val secretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            val keyChars = Base64.encode(secretKey.encoded)
            KLogger.d { "DesktopEncryptionSettingsFactory: generating new master key (${profile.masterKeyName})" }
            credentialStorage.add(profile.masterKeyName, StoredCredential(MASTER_KEY_USER, keyChars.toCharArray()))
            secretKey
        } else {
            val decodedKey = Base64.decode(storedMasterKey.concatToString())
            SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")
        }
    }
}

internal class EncryptedPreferences(
    private val secretKey: Key,
    private val delegate: Preferences,
    javaRandom: SecureRandom = SecureRandom(),
) : Preferences() {
    private companion object {
        const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
        const val IV_SIZE_BYTES = 12
        const val TAG_LENGTH_BIT = 128

        /**
         * `java.util.prefs` refuses any value over 8192 chars (`AbstractPreferences.MAX_VALUE_LENGTH`),
         * and the trusted-device list is one encrypted value that crosses that line at two
         * post-quantum pairings. Encrypted payloads longer than this are therefore split across
         * `<key>#0..#n-1` entries, with the main key holding a `chunks:<n>` marker. The marker can
         * never collide with real data: every stored value is otherwise base64, which has no ':'.
         * Values at or under the limit keep the old single-entry shape, so pre-chunking installs
         * read back unchanged. Kept well under 8192 for headroom, not correctness.
         */
        const val CHUNK_LIMIT = 6000
        const val CHUNK_MARKER = "chunks:"

        /** Backstop when parsing a marker: a corrupt count must not drive an unbounded read loop. */
        const val MAX_CHUNKS = 10_000
    }

    private val random = javaRandom.asKotlinRandom()

    @OptIn(ExperimentalEncodingApi::class)
    private fun decryptWithIV(encryptedData: String?, ivSize: Int = IV_SIZE_BYTES): String? = encryptedData?.let {
        val rawData = Base64.decode(it)
        val iv = rawData.copyOfRange(0, ivSize)
        val encryptedValue = rawData.copyOfRange(ivSize, rawData.size)
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING).apply {
            init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BIT, iv))
        }
        cipher.doFinal(encryptedValue).decodeToString()
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encryptWithIV(value: String?, iv: ByteArray = random.nextBytes(IV_SIZE_BYTES)): String? = value?.let {
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BIT, iv))
        val encryptedValue = cipher.doFinal(it.toByteArray())
        Base64.encode(iv + encryptedValue)
    }

    private fun encryptWithHashedIV(value: String?): String? {
        val iv = value?.let { deterministicIv(it) }
        return iv?.let { encryptWithIV(value, it) }
    }

    private fun deterministicIv(value: String): ByteArray {
        // SHA-256 of the value, truncated to IV_SIZE_BYTES. Always exactly IV_SIZE_BYTES bytes
        // regardless of input length, and deterministic so the same key always produces the same
        // ciphertext (lets us look up entries by re-encrypting the key).
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.copyOfRange(0, IV_SIZE_BYTES)
    }

    private fun putEncrypted(key: String?, value: String?) {
        val encoded = encryptWithIV(value)
        val staleChunks = chunkCount(delegate.get(encryptWithHashedIV(key), null))
        if (encoded == null || encoded.length <= CHUNK_LIMIT) {
            delegate.put(encryptWithHashedIV(key), encoded)
            dropChunks(key, from = 0, until = staleChunks)
            return
        }
        // Chunks first, marker last: a reader that interleaves sees the old value until the
        // marker flips, never a half-written new one. Stale tail entries from a previously
        // larger value go last for the same reason.
        val chunks = encoded.chunked(CHUNK_LIMIT)
        chunks.forEachIndexed { index, chunk ->
            delegate.put(encryptWithHashedIV(chunkKey(key, index)), chunk)
        }
        delegate.put(encryptWithHashedIV(key), CHUNK_MARKER + chunks.size)
        dropChunks(key, from = chunks.size, until = staleChunks)
    }

    private fun getDecrypted(key: String?): String? {
        val raw = delegate.get(encryptWithHashedIV(key), null) ?: return null
        val chunks = chunkCount(raw)
        if (chunks == 0) return decryptWithIV(raw)
        val encoded = buildString {
            for (index in 0 until chunks) {
                // A missing chunk means a torn write; absent beats feeding GCM a truncated blob.
                append(delegate.get(encryptWithHashedIV(chunkKey(key, index)), null) ?: return null)
            }
        }
        return decryptWithIV(encoded)
    }

    /** `<key>#<index>` stays short enough that its encrypted form fits the 80-char prefs key cap. */
    private fun chunkKey(key: String?, index: Int) = "$key#$index"

    private fun chunkCount(raw: String?): Int {
        if (raw == null || !raw.startsWith(CHUNK_MARKER)) return 0
        return raw.removePrefix(CHUNK_MARKER).toIntOrNull()?.coerceIn(0, MAX_CHUNKS) ?: 0
    }

    private fun dropChunks(key: String?, from: Int, until: Int) {
        for (index in from until until) {
            delegate.remove(encryptWithHashedIV(chunkKey(key, index)))
        }
    }

    override fun toString() = "EncryptedPreferences"
    override fun put(p0: String?, p1: String?) = putEncrypted(p0, p1)
    override fun get(p0: String?, p1: String?): String? = getDecrypted(p0) ?: p1
    override fun remove(p0: String?) {
        dropChunks(p0, from = 0, until = chunkCount(delegate.get(encryptWithHashedIV(p0), null)))
        delegate.remove(encryptWithHashedIV(p0))
    }
    override fun clear() = delegate.clear()
    override fun putInt(p0: String?, p1: Int) = put(p0, p1.toString())
    override fun getInt(p0: String?, p1: Int): Int = get(p0, null)?.toInt() ?: p1
    override fun putLong(p0: String?, p1: Long) = put(p0, p1.toString())
    override fun getLong(p0: String?, p1: Long): Long = get(p0, null)?.toLong() ?: p1
    override fun putBoolean(p0: String?, p1: Boolean) = put(p0, p1.toString())
    override fun getBoolean(p0: String?, p1: Boolean): Boolean = get(p0, p1.toString()).toBoolean()
    override fun putFloat(p0: String?, p1: Float) = put(p0, p1.toString())
    override fun getFloat(p0: String?, p1: Float): Float = get(p0, null)?.toFloat() ?: p1
    override fun putDouble(p0: String?, p1: Double) = put(p0, p1.toString())
    override fun getDouble(p0: String?, p1: Double): Double = get(p0, null)?.toDouble() ?: p1
    override fun putByteArray(p0: String?, p1: ByteArray?) = put(p0, p1.toString())
    override fun getByteArray(p0: String?, p1: ByteArray?): ByteArray? = get(p0, null)?.toByteArray() ?: p1
    override fun keys(): Array<String?> = delegate.keys().map { decryptWithIV(it) }.toTypedArray()
    override fun childrenNames(): Array<String> = delegate.childrenNames()
    override fun parent(): Preferences = delegate.parent()
    override fun node(p0: String?): Preferences = delegate.node(p0)
    override fun nodeExists(p0: String?): Boolean = delegate.nodeExists(p0)
    override fun removeNode() = delegate.removeNode()
    override fun name(): String = delegate.name()
    override fun absolutePath(): String = delegate.absolutePath()
    override fun isUserNode(): Boolean = delegate.isUserNode
    override fun flush() = delegate.flush()
    override fun sync() = delegate.sync()

    private val preferenceChangeListeners = mutableMapOf<PreferenceChangeListener, PreferenceChangeListener>()
    override fun addPreferenceChangeListener(p0: PreferenceChangeListener?) {
        p0?.let {
            val listener = PreferenceChangeListener { event ->
                val decryptedKey = decryptWithIV(event.key)
                val decryptedNewValue = decryptWithIV(event.newValue)
                p0.preferenceChange(PreferenceChangeEvent(this, decryptedKey, decryptedNewValue))
            }
            preferenceChangeListeners[it] = listener
            delegate.addPreferenceChangeListener(listener)
        }
    }

    override fun removePreferenceChangeListener(p0: PreferenceChangeListener?) {
        p0?.let {
            val listener = preferenceChangeListeners.remove(p0)
            listener?.let { delegate.removePreferenceChangeListener(it) }
        }
    }

    override fun addNodeChangeListener(p0: NodeChangeListener?) = delegate.addNodeChangeListener(p0)
    override fun removeNodeChangeListener(p0: NodeChangeListener?) = delegate.removeNodeChangeListener(p0)
    override fun exportNode(p0: OutputStream?) = delegate.exportNode(p0)
    override fun exportSubtree(p0: OutputStream?) = delegate.exportSubtree(p0)
}
