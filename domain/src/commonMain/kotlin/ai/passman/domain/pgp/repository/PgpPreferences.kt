package ai.passman.domain.pgp.repository

import ai.passman.domain.pgp.model.PgpKey

interface PgpPreferences {
    suspend fun getPgpKeyList(): List<PgpKey>
    suspend fun addPgpKey(pgpKey: PgpKey)
    suspend fun addPgpKeys(pgpKeys: List<PgpKey>)

    /**
     * Whether the bundled developer key's once-per-account auto-import already ran for
     * [userName]. Deliberately a preference rather than a marker file in the pgp directory
     * (which syncs between devices), and deliberately never cleared on key deletion: a user
     * who removes the developer key must not have it silently re-imported on next login.
     */
    suspend fun isDeveloperKeyImported(userName: String): Boolean
    suspend fun setDeveloperKeyImported(userName: String)
}
