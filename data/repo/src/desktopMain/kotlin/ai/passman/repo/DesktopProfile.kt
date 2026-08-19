package ai.passman.repo

/**
 * Runtime profile (debug vs prod) for the Desktop build.
 *
 * This is a *build variant*, decided at compile time, not a runtime flag: `apps/desk` has
 * `src/debug` and `src/prod` source directories in the spirit of Android build types, exactly one
 * of which is compiled in, and each supplies an `ai.passman.di.buildVariantModule` that binds the
 * matching instance here. Nothing reads a system property, so there is no way to launch the app —
 * from Gradle, from an IDE run configuration, or from a packaged binary — and silently land in the
 * wrong profile.
 *
 * Debug and prod are fully isolated: separate filesystem data dir, separate `java.util.prefs` node
 * for encrypted preferences, and separate credential-storage master key name. That isolation is the
 * point — a developer build must never touch a real vault — so anything profile-dependent belongs
 * here rather than being derived independently somewhere else.
 */
data class DesktopProfile(val isDebug: Boolean) {

    /** Subdirectory of the user's home (or %APPDATA%) where vault files, keystores, PGP keys, and logs live. */
    val dataDirName: String = if (isDebug) "passman_debug" else "passman"

    /** `java.util.prefs` node name used by `DesktopEncryptionSettingsFactory.EncryptedPreferences`. */
    val encryptedNodeName: String = if (isDebug) "ai.passman.platform.debug" else "ai.passman.platform"

    /** Credential-storage entry name for the AES master key that encrypts the prefs node. */
    val masterKeyName: String = if (isDebug) "passmanMasterKey_debug" else "passmanMasterKey"

    companion object {
        val Debug = DesktopProfile(isDebug = true)
        val Prod = DesktopProfile(isDebug = false)
    }
}
