package ai.passman.platform.prefs

import ai.passman.logging.KLogger
import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.russhwolf.settings.Settings
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Encrypted preference storage backed directly by the Android Keystore.
 *
 * Replaces androidx.security.crypto's EncryptedSharedPreferences, whose entire API was
 * deprecated as of 1.1.0-beta01 in favour of using the platform Keystore directly.
 *
 * The scheme mirrors DesktopEncryptionSettingsFactory so both platforms behave the same:
 * values get a fresh random IV per write, and keys get a deterministic IV derived from the
 * key itself so an entry can still be found by re-encrypting its key. Deterministic key
 * encryption reveals equality between keys, which is inherent to any lookup-by-key scheme
 * and is what EncryptedSharedPreferences did as well (AES-SIV for keys, AES-GCM for values).
 */
class AndroidEncryptionSettingsFactory(private val context: Context) : EncryptionSettingsFactory {

    override fun createEncrypted(name: String): Settings {
        val crypto = KeystoreCrypto(loadOrCreateMasterKey())
        val prefs = context.getSharedPreferences(storeName(name), Context.MODE_PRIVATE)
        migrateLegacyStore(name, prefs, crypto)
        return EncryptedSettings(prefs, crypto)
    }

    private fun loadOrCreateMasterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let {
            return it.secretKey
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE_BITS)
                // Required so keys can be encrypted with a caller-supplied deterministic IV.
                // Values still use a fresh random IV per write, which is where it matters.
                .setRandomizedEncryptionRequired(false)
                .build(),
        )
        KLogger.d { "AndroidEncryptionSettingsFactory: generating master key ($MASTER_KEY_ALIAS)" }
        return generator.generateKey()
    }

    /**
     * One-release migration off EncryptedSharedPreferences.
     *
     * The new store uses a different file name on purpose, so the legacy file is read and
     * removed without the two formats ever sharing a file. Once every install has been
     * through this, delete this function, the androidx.security.crypto dependency, and the
     * two legacy imports above.
     */
    private fun migrateLegacyStore(name: String, target: SharedPreferences, crypto: KeystoreCrypto) {
        if (target.getBoolean(MIGRATION_MARKER, false)) return

        val legacyFile = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
        if (!legacyFile.exists()) {
            target.edit().putBoolean(MIGRATION_MARKER, true).apply()
            return
        }

        val migrated = runCatching {
            val masterKey = MasterKey.Builder(context, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            @Suppress("DEPRECATION")
            val legacy = EncryptedSharedPreferences.create(
                context,
                name,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            val entries = legacy.all
            val editor = target.edit()
            entries.forEach { (key, value) ->
                when (value) {
                    is String -> editor.putString(crypto.encryptKey(key), crypto.encryptValue(value))
                    is Int, is Long, is Float, is Boolean ->
                        editor.putString(crypto.encryptKey(key), crypto.encryptValue(value.toString()))
                    else -> KLogger.d {
                        "AndroidEncryptionSettingsFactory: skipping unsupported entry type in '$name'"
                    }
                }
            }
            editor.putBoolean(MIGRATION_MARKER, true).commit()
            entries.size
        }

        migrated.onSuccess { count ->
            context.deleteSharedPreferences(name)
            KLogger.d { "AndroidEncryptionSettingsFactory: migrated $count entries from legacy '$name'" }
        }.onFailure { error ->
            // Leave the legacy file in place and do not set the marker, so the next launch
            // retries instead of silently starting from an empty store.
            KLogger.d {
                "AndroidEncryptionSettingsFactory: legacy migration of '$name' failed: ${error.message}"
            }
        }
    }

    private fun storeName(name: String) = "${name}_ks"

    internal companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val MASTER_KEY_ALIAS = "passman_prefs_master_key"
        const val KEY_SIZE_BITS = 256

        /** Plaintext key, never a user value, so it is readable without decryption. */
        const val MIGRATION_MARKER = "__passman_migrated_from_esp__"
    }
}

internal class KeystoreCrypto(private val secretKey: SecretKey) {

    @OptIn(ExperimentalEncodingApi::class)
    fun encryptValue(value: String): String {
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING).apply { init(Cipher.ENCRYPT_MODE, secretKey) }
        return Base64.encode(cipher.iv + cipher.doFinal(value.toByteArray()))
    }

    /** Deterministic, so a stored entry can be located by re-encrypting its key. */
    @OptIn(ExperimentalEncodingApi::class)
    fun encryptKey(key: String): String {
        val iv = MessageDigest.getInstance("SHA-256").digest(key.toByteArray()).copyOf(IV_SIZE_BYTES)
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING).apply {
            init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, iv))
        }
        return Base64.encode(iv + cipher.doFinal(key.toByteArray()))
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun decrypt(encoded: String): String? = runCatching {
        val raw = Base64.decode(encoded)
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING).apply {
            init(
                Cipher.DECRYPT_MODE,
                secretKey,
                GCMParameterSpec(TAG_LENGTH_BITS, raw.copyOfRange(0, IV_SIZE_BYTES)),
            )
        }
        cipher.doFinal(raw.copyOfRange(IV_SIZE_BYTES, raw.size)).decodeToString()
    }.getOrNull()

    private companion object {
        const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
        const val IV_SIZE_BYTES = 12
        const val TAG_LENGTH_BITS = 128
    }
}

/**
 * Stores every value as an encrypted string. Non-string types round-trip through their
 * string form, which keeps the on-disk format uniform and the crypto path single.
 */
internal class EncryptedSettings(
    private val prefs: SharedPreferences,
    private val crypto: KeystoreCrypto,
) : Settings {

    private val marker = AndroidEncryptionSettingsFactory.MIGRATION_MARKER

    override val keys: Set<String>
        get() = prefs.all.keys.filterNot { it == marker }.mapNotNull(crypto::decrypt).toSet()

    override val size: Int get() = prefs.all.keys.count { it != marker }

    override fun clear() {
        val editor = prefs.edit()
        prefs.all.keys.filterNot { it == marker }.forEach(editor::remove)
        editor.apply()
    }

    override fun remove(key: String) = prefs.edit().remove(crypto.encryptKey(key)).apply()

    override fun hasKey(key: String): Boolean = prefs.contains(crypto.encryptKey(key))

    private fun putRaw(key: String, value: String) =
        prefs.edit().putString(crypto.encryptKey(key), crypto.encryptValue(value)).apply()

    private fun getRaw(key: String): String? =
        prefs.getString(crypto.encryptKey(key), null)?.let(crypto::decrypt)

    override fun putString(key: String, value: String) = putRaw(key, value)
    override fun getString(key: String, defaultValue: String): String = getRaw(key) ?: defaultValue
    override fun getStringOrNull(key: String): String? = getRaw(key)

    override fun putInt(key: String, value: Int) = putRaw(key, value.toString())
    override fun getInt(key: String, defaultValue: Int): Int = getIntOrNull(key) ?: defaultValue
    override fun getIntOrNull(key: String): Int? = getRaw(key)?.toIntOrNull()

    override fun putLong(key: String, value: Long) = putRaw(key, value.toString())
    override fun getLong(key: String, defaultValue: Long): Long = getLongOrNull(key) ?: defaultValue
    override fun getLongOrNull(key: String): Long? = getRaw(key)?.toLongOrNull()

    override fun putFloat(key: String, value: Float) = putRaw(key, value.toString())
    override fun getFloat(key: String, defaultValue: Float): Float = getFloatOrNull(key) ?: defaultValue
    override fun getFloatOrNull(key: String): Float? = getRaw(key)?.toFloatOrNull()

    override fun putDouble(key: String, value: Double) = putRaw(key, value.toString())
    override fun getDouble(key: String, defaultValue: Double): Double = getDoubleOrNull(key) ?: defaultValue
    override fun getDoubleOrNull(key: String): Double? = getRaw(key)?.toDoubleOrNull()

    override fun putBoolean(key: String, value: Boolean) = putRaw(key, value.toString())
    override fun getBoolean(key: String, defaultValue: Boolean): Boolean = getBooleanOrNull(key) ?: defaultValue
    override fun getBooleanOrNull(key: String): Boolean? = getRaw(key)?.toBooleanStrictOrNull()
}
