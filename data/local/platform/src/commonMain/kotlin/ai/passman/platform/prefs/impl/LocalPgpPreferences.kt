package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.repository.PgpPreferences
import com.russhwolf.settings.Settings
import kotlinx.serialization.json.Json

class LocalPgpPreferences(
    encryptedFactory: EncryptionSettingsFactory,
) : PgpPreferences {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)
    private val format = Json { ignoreUnknownKeys = true }

    override suspend fun getPgpKeyList(): List<PgpKey> {
        val raw = settings.getStringOrNull(PGP_LIST) ?: return emptyList()
        return runCatching { format.decodeFromString<List<PgpKey>>(migrateLegacyKeyTypes(raw)) }
            .getOrElse { emptyList() }
    }

    // Entries written before the ai.sterling.passman -> ai.passman rename carry the old
    // fully-qualified PgpKeyType discriminators; PgpKeyType now pins "secret"/"public".
    private fun migrateLegacyKeyTypes(raw: String): String = raw
        .replace("\"ai.sterling.passman.domain.pgp.model.PgpKeyType.Secret\"", "\"secret\"")
        .replace("\"ai.sterling.passman.domain.pgp.model.PgpKeyType.Public\"", "\"public\"")

    override suspend fun addPgpKey(pgpKey: PgpKey) {
        val current = getPgpKeyList().toMutableList()
        current.add(pgpKey)
        settings.putString(PGP_LIST, format.encodeToString(current))
    }

    override suspend fun addPgpKeys(pgpKeys: List<PgpKey>) {
        val current = getPgpKeyList().toMutableList()
        current.addAll(pgpKeys)
        settings.putString(PGP_LIST, format.encodeToString(current))
    }

    // Keyed per account: the store is shared by every account on the device, and one user's
    // auto-import (or later deletion) must not decide another's. Plain key suffix — Settings
    // keys are opaque map keys, unlike store NAMES (see LocalTrustedDevicesRepository).
    override suspend fun isDeveloperKeyImported(userName: String): Boolean =
        settings.getBoolean(developerKeyImportedKey(userName), false)

    override suspend fun setDeveloperKeyImported(userName: String) {
        settings.putBoolean(developerKeyImportedKey(userName), true)
    }

    private fun developerKeyImportedKey(userName: String) = "$DEVELOPER_KEY_IMPORTED_PREFIX$userName"

    // Same per-account, never-cleared-on-deletion semantics as the developer-key flag above: the
    // flag is what makes deleting the default rings (or their vault entry) final on this device.
    override suspend fun isDefaultRingsProvisioned(userName: String): Boolean =
        settings.getBoolean(defaultRingsProvisionedKey(userName), false)

    override suspend fun setDefaultRingsProvisioned(userName: String) {
        settings.putBoolean(defaultRingsProvisionedKey(userName), true)
    }

    private fun defaultRingsProvisionedKey(userName: String) = "$DEFAULT_RINGS_PROVISIONED_PREFIX$userName"

    private companion object {
        const val PREFS_NAME = "pgp_prefs"
        const val PGP_LIST = "pgp_keys"
        const val DEVELOPER_KEY_IMPORTED_PREFIX = "developer_key_imported_"
        const val DEFAULT_RINGS_PROVISIONED_PREFIX = "default_rings_provisioned_"
    }
}
