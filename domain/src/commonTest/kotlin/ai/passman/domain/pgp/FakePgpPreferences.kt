package ai.passman.domain.pgp

import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.repository.PgpPreferences

/** In-memory [PgpPreferences]: the flags work; the key-list methods fail loudly. */
class FakePgpPreferences : PgpPreferences {
    private val defaultRingsProvisioned = mutableSetOf<String>()
    private val developerKeyImported = mutableSetOf<String>()

    fun isProvisionedFlagSet(userName: String): Boolean = userName in defaultRingsProvisioned
    fun presetProvisionedFlag(userName: String) {
        defaultRingsProvisioned += userName
    }

    override suspend fun isDefaultRingsProvisioned(userName: String): Boolean = userName in defaultRingsProvisioned

    override suspend fun setDefaultRingsProvisioned(userName: String) {
        defaultRingsProvisioned += userName
    }

    override suspend fun isDeveloperKeyImported(userName: String): Boolean = userName in developerKeyImported

    override suspend fun setDeveloperKeyImported(userName: String) {
        developerKeyImported += userName
    }

    override suspend fun getPgpKeyList(): List<PgpKey> =
        throw UnsupportedOperationException("FakePgpPreferences.getPgpKeyList was not configured")

    override suspend fun addPgpKey(pgpKey: PgpKey): Unit =
        throw UnsupportedOperationException("FakePgpPreferences.addPgpKey was not configured")

    override suspend fun addPgpKeys(pgpKeys: List<PgpKey>): Unit =
        throw UnsupportedOperationException("FakePgpPreferences.addPgpKeys was not configured")
}
