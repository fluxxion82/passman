plugins {
    id("passman.kmp.android")
    id("passman.compose")
    alias(libs.plugins.kotlin.serialization)
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.screens"
    }
    jvm("desktop")
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        getByName("commonMain") {
            dependencies {
                implementation(project(path = ":domain"))
                implementation(project(path = ":logging:logger"))
                implementation(project(":presentation:design"))
                implementation(project(":presentation:viewmodel"))
                implementation(project(":presentation:viewvo"))

                implementation(libs.kotlinx.datetime)
                implementation(libs.kotlinx.serialization)
                implementation(libs.navigation.compose)
                implementation(libs.navigation.material.compose)

                implementation(libs.compose.runtime)
                implementation(libs.compose.material3)
                implementation(libs.compose.material.icons.extended)
                implementation(libs.compose.ui)
                implementation(libs.compose.animation)
                implementation(libs.compose.foundation)
                implementation(libs.compose.components.resources)
                implementation(libs.compose.ui.tooling.preview)

                implementation(libs.koin.core)
                implementation(libs.koin.compose)
                implementation(libs.koin.composeVM)
            }
        }
        getByName("commonTest") {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        getByName("desktopMain") {
            dependencies {
                implementation(compose.desktop.currentOs)
                implementation(libs.compose.ui.tooling.preview)
            }
        }
        getByName("androidMain") {
            dependencies {
                implementation(libs.accompanist.permissions)
                implementation(libs.androidx.activity.compose)
                implementation(libs.compose.ui.tooling.preview)
            }
        }
    }
}

compose.resources {
    generateResClass = always
}
