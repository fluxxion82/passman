pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven { setUrl("https://plugins.gradle.org/m2/") }
    }
}

dependencyResolutionManagement {
    @Suppress("UnstableApiUsage")
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven("https://jitpack.io")
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    }
    // gradle/libs.versions.toml is picked up as `libs` automatically.
}

rootProject.name = "passman"

// Apps
include(":apps:droid")
include(":apps:desk")
include(":iosdi")

// Presentation
include(":presentation:screens")
include(":presentation:design")
include(":presentation:viewmodel")
include(":presentation:viewvo")

// Domain
include(":domain")

// Data
include(":data:crypto")
include(":data:pgp")
include(":data:keystore")
include(":data:cache")
include(":data:repo")
include(":data:local:platform")

// Logging
include(":logging:logger")
include(":logging:platformlogger")

// k2k is a separate repo (Apache-2.0) vendored in as a submodule; see README.
include(":k2k")
project(":k2k").projectDir = file("k2k/k2k")
