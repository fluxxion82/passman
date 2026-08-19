package ai.passman.di.config

import ai.passman.domain.identification.model.DeviceInfo
import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import ai.passman.repo.DesktopProfile
import org.koin.dsl.module

val buildConfigModule = module {
    single {
        // Everything variant-dependent comes from the injected profile. Deriving any of it
        // independently here is how a debug build ends up naming the production data directory.
        val profile: DesktopProfile = get()
        AppInformation(
            version = "1.0.0".toVersion(),
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
