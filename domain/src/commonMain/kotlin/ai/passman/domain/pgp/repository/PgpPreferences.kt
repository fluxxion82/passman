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

    /**
     * Whether the default PGP rings (and their vault entry) were already provisioned for
     * [userName] on this device — see [ai.passman.domain.pgp.EnsureDefaultPgpRings]. Set once
     * the ring passphrase is safely recorded in the vault, and also when the guard finds the
     * account already has keys or the entry (legacy accounts, synced artifacts), so a deliberate
     * key deletion is never undone by the next login. Device-local, like
     * [isDeveloperKeyImported], and for the same reason.
     */
    suspend fun isDefaultRingsProvisioned(userName: String): Boolean
    suspend fun setDefaultRingsProvisioned(userName: String)
}
