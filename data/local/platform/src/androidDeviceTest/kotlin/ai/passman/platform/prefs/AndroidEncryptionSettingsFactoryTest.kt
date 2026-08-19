package ai.passman.platform.prefs

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.security.KeyStore
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Covers the replacement of the deprecated EncryptedSharedPreferences with a Keystore-backed
 * store, and specifically that an existing install does not lose its data.
 *
 * Needs a device or emulator: both EncryptedSharedPreferences and the Android Keystore are
 * unavailable on the JVM.
 */
@RunWith(AndroidJUnit4::class)
class AndroidEncryptionSettingsFactoryTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun clearState() {
        listOf(LEGACY_STORE, ROUNDTRIP_STORE).forEach { name ->
            context.deleteSharedPreferences(name)
            context.deleteSharedPreferences("${name}_ks")
        }
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .takeIf { it.containsAlias(MASTER_KEY_ALIAS) }
            ?.deleteEntry(MASTER_KEY_ALIAS)
    }

    @Test
    fun valuesRoundTripThroughTheKeystoreBackedStore() {
        val settings = AndroidEncryptionSettingsFactory(context).createEncrypted(ROUNDTRIP_STORE)

        settings.putString("pgp_private_key", "SECRET-PRIVATE-KEY")
        settings.putInt("count", 7)
        settings.putBoolean("enabled", true)

        assertEquals("SECRET-PRIVATE-KEY", settings.getStringOrNull("pgp_private_key"))
        assertEquals(7, settings.getIntOrNull("count"))
        assertEquals(true, settings.getBooleanOrNull("enabled"))
        assertTrue(settings.hasKey("pgp_private_key"))
        assertEquals(setOf("pgp_private_key", "count", "enabled"), settings.keys)

        settings.remove("count")
        assertNull(settings.getIntOrNull("count"))
    }

    /** Nothing readable may be left on disk in plaintext. */
    @Test
    fun keysAndValuesAreNotStoredInPlaintext() {
        val settings = AndroidEncryptionSettingsFactory(context).createEncrypted(ROUNDTRIP_STORE)
        settings.putString("pgp_private_key", "SECRET-PRIVATE-KEY")

        val raw = context.getSharedPreferences("${ROUNDTRIP_STORE}_ks", Context.MODE_PRIVATE).all
        assertTrue(raw.keys.none { it.contains("pgp_private_key") }, "key stored in plaintext")
        assertTrue(
            raw.values.filterIsInstance<String>().none { it.contains("SECRET-PRIVATE-KEY") },
            "value stored in plaintext",
        )
    }

    /**
     * The one that matters: an install holding data written by the deprecated
     * EncryptedSharedPreferences must still be able to read it after the swap.
     */
    @Test
    fun existingEncryptedSharedPreferencesDataSurvivesMigration() {
        writeLegacyEntries(
            "pgp_private_key" to "LEGACY-PRIVATE-KEY",
            "keystore_path" to "/data/keystore/passman.pfx",
            "trusted_device_1" to "device-fingerprint-abc",
        )

        val settings = AndroidEncryptionSettingsFactory(context).createEncrypted(LEGACY_STORE)

        assertEquals("LEGACY-PRIVATE-KEY", settings.getStringOrNull("pgp_private_key"))
        assertEquals("/data/keystore/passman.pfx", settings.getStringOrNull("keystore_path"))
        assertEquals("device-fingerprint-abc", settings.getStringOrNull("trusted_device_1"))
    }

    @Test
    fun legacyStoreIsRemovedOnceMigrated() {
        writeLegacyEntries("pgp_private_key" to "LEGACY-PRIVATE-KEY")
        val legacyFile = File(context.applicationInfo.dataDir, "shared_prefs/$LEGACY_STORE.xml")
        assertTrue(legacyFile.exists(), "precondition: legacy file should exist")

        AndroidEncryptionSettingsFactory(context).createEncrypted(LEGACY_STORE)

        assertTrue(!legacyFile.exists(), "legacy store should be deleted after migration")
    }

    /** Re-running the factory must not wipe or duplicate already-migrated data. */
    @Test
    fun migrationIsIdempotent() {
        writeLegacyEntries("pgp_private_key" to "LEGACY-PRIVATE-KEY")

        val factory = AndroidEncryptionSettingsFactory(context)
        factory.createEncrypted(LEGACY_STORE)
        val second = factory.createEncrypted(LEGACY_STORE)

        assertEquals("LEGACY-PRIVATE-KEY", second.getStringOrNull("pgp_private_key"))
        assertEquals(1, second.size)
    }

    private fun writeLegacyEntries(vararg entries: Pair<String, String>) {
        val masterKey = MasterKey.Builder(context, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        @Suppress("DEPRECATION")
        val legacy = EncryptedSharedPreferences.create(
            context,
            LEGACY_STORE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        legacy.edit().apply { entries.forEach { (k, v) -> putString(k, v) } }.commit()
    }

    private companion object {
        const val LEGACY_STORE = "migration_test_store"
        const val ROUNDTRIP_STORE = "roundtrip_test_store"
        const val MASTER_KEY_ALIAS = "passman_prefs_master_key"
    }
}
