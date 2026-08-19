plugins {
    id("passman.kmp")
    id("passman.test")
    alias(libs.plugins.kotlin.serialization)
}

group = "ai.passman.domain"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    // ios()
    // Note: iosSimulatorArm64 target requires that all dependencies have M1 support
    // iosSimulatorArm64()
    js {
        browser()
        binaries.executable()
    }
    jvm()

    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            isStatic = true
        }
    }

    sourceSets {
        getByName("commonMain") {
            dependencies {
                implementation(libs.kotlinx.serialization)
                implementation(libs.kotlinx.coroutines.core)

                implementation(libs.kotlinx.datetime)

                implementation(libs.koin.core)

                implementation(project(":logging:logger"))
            }
        }
        getByName("jsTest") {
            dependencies {
                implementation(libs.kotlin.test.js)
            }
        }
    }
}
