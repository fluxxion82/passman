package ai.passman.repo

/**
 * Runtime profile (debug vs prod) for the Desktop build.
 *
 * Selected via the JVM system property `passman.profile`. The `:apps:desk:run` Gradle task
 * sets `-Dpassman.profile=debug`. Packaged native distributions (`packageDmg` / `packageMsi`
 * / `packageDeb`) do not inherit that arg, so the prod-packaged binary runs without the flag
 * and defaults to the prod profile.
 *
 * Debug and prod are fully isolated: separate filesystem data dir, separate `java.util.prefs`
 * node for encrypted preferences, and separate credential-storage master key name.
 */
object DesktopProfile {
    private val profile: String = System.getProperty("passman.profile", "prod")
    val isDebug: Boolean = profile == "debug"

    /** Subdirectory of the user's home (or %APPDATA%) where vault files, keystores, PGP keys, and logs live. */
    val dataDirName: String = if (isDebug) "passman_debug" else "passman"

    /** `java.util.prefs` node name used by `DesktopEncryptionSettingsFactory.EncryptedPreferences`. */
    val encryptedNodeName: String = if (isDebug) "ai.passman.platform.debug" else "ai.passman.platform"

    /** Credential-storage entry name for the AES master key that encrypts the prefs node. */
    val masterKeyName: String = if (isDebug) "passmanMasterKey_debug" else "passmanMasterKey"
}
