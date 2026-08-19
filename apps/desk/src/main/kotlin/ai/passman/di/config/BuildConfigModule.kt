package ai.passman.di.config

import ai.passman.domain.identification.model.DeviceInfo
import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import org.koin.dsl.module

val buildConfigModule = module {
    single {
        AppInformation(
            version = "1.0.0".toVersion(),
            versionCode = 1,
            id = "ai.passman",
            environment = "dev".toEnvironment(),
            debug = true,
            userHomeDir = (System.getenv("APPDATA") ?: System.getProperty("user.home")) + "/passman"
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

private fun String.toEnvironment(): Environment {
    return when (this) {
        "dev" -> Environment.SANDBOX
        "staging" -> Environment.STAGING
        "prod" -> Environment.PROD
        else -> Environment.SANDBOX
    }
}
