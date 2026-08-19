plugins {
    id("passman.kmp.android")
    id("passman.compose")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.design"
    }
    jvm("desktop")
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain = getByName("commonMain") {
            dependencies {
                implementation(project(path = ":domain"))
                implementation(project(path = ":logging:logger"))

                implementation(libs.kotlinx.datetime)

                implementation(libs.compose.runtime)
                implementation(libs.compose.material3)
                implementation(libs.compose.ui)
                implementation(libs.compose.animation)
                implementation(libs.compose.foundation)
                implementation(libs.compose.components.resources)
                implementation(libs.compose.material.icons.extended)
            }
        }
        getByName("commonTest") {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        getByName("desktopMain") {
            dependencies {
                implementation(libs.compose.foundation)
                implementation(compose.desktop.currentOs)

                // QR encode for pairing codes (QRCodeWriter). Android already declares it below
                // for the scanner; this module has no shared jvm/android source set to hold it.
                implementation(libs.zxing.core)
            }
        }
        getByName("androidMain") {
            dependencies {
                // Was pinned here at 2025.04.00 while every other module used the catalog's
                // BOM. Unifying on the catalog moves this source set forward ~14 months.
                // No androidx compose-bom and no androidx.compose.* artifacts here.
                // commonMain already supplies foundation, ui and material through Compose
                // Multiplatform, which resolves to the androidx artifacts on Android — the
                // BOM was a second, disagreeing version source for the same classes.
                implementation(libs.compose.ui.tooling.preview)
                implementation(libs.compose.components.ui.tooling.preview)
                implementation(libs.androidx.activity.compose)

                // Live QR scan for TOTP seeds (Android-only; desktop imports from an image).
                // zxing below also encodes the pairing QR, which both platforms render.
                implementation(libs.accompanist.permissions)
                implementation(libs.androidx.camera.camera2)
                implementation(libs.androidx.camera.lifecycle)
                implementation(libs.androidx.camera.view)
                implementation(libs.zxing.core)
            }
        }
    }
}

//because the dependency on the compose library is a project dependency
compose.resources {
    generateResClass = always
}
