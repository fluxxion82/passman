package ai.passman.android.di

import ai.passman.android.BuildConfig
import ai.passman.domain.identification.model.DeviceInfo
import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import android.os.Build
import org.koin.android.ext.koin.androidContext
import org.koin.dsl.module

val buildConfigModule = module {
    single {
        AppInformation(
            version = BuildConfig.VERSION_NAME.toVersion(),
            versionCode = BuildConfig.VERSION_CODE,
            id = BuildConfig.APPLICATION_ID,
            environment = BuildConfig.APPLICATION_ID.toEnvironment(),
            debug = BuildConfig.DEBUG,
            userHomeDir = androidContext().filesDir.path
        )
    }

    single {
        DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            frameworkApiVersion = Build.VERSION.SDK_INT
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
        additionalInfo = if (BuildConfig.VERSION_NAME.contains("dirty")) "dirty" else ""
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
