package ai.passman.di.config

import ai.passman.domain.identification.model.DeviceInfo
import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import ai.passman.repo.DesktopProfile
import java.util.Properties
import org.koin.dsl.module

val buildConfigModule = module {
    single {
        // Everything variant-dependent comes from the injected profile. Deriving any of it
        // independently here is how a debug build ends up naming the production data directory.
        val profile: DesktopProfile = get()
        AppInformation(
            version = desktopVersionName().toVersion(),
            versionCode = 1,
            id = "ai.passman",
            environment = if (profile.isDebug) Environment.SANDBOX else Environment.PROD,
            debug = profile.isDebug,
            userHomeDir = (System.getenv("APPDATA") ?: System.getProperty("user.home")) +
                "/" + profile.dataDirName,
        )
    }

    single {
        DeviceInfo(
            manufacturer = "Mac",
            model = "Notebook",
            frameworkApiVersion = 1,
        )
    }
}

/**
 * The version string the build stamped into `passman-version.properties`, which is generated from
 * the `version` in `apps/desk/build.gradle.kts`. It is read rather than written here because the
 * literal that used to live in this file went stale silently — nothing fails when the number is
 * wrong, it just names the wrong build to whoever reads it in Settings.
 *
 * The fallback covers running from a classpath that has no generated resources on it, e.g. a test.
 */
internal fun desktopVersionName(): String =
    object {}.javaClass.getResourceAsStream("/passman-version.properties")?.use { stream ->
        Properties().apply { load(stream) }.getProperty("version")
    } ?: "0.0.0"

internal fun String.toVersion(): Version {
    val splitVersion = if (isEmpty()) {
        listOf("0.0.0", "0")
    } else if (!contains("_")) {
        listOf(this, "0")
    } else {
        this.split("_").map { it }
    }

    return Version(
        name = splitVersion[0],
        build = splitVersion[1].substringBefore("-", splitVersion[1].substringBefore(".", splitVersion[1])),
        additionalInfo = ""
    )
}
