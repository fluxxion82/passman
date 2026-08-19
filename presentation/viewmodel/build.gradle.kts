plugins {
    id("passman.kmp.android")
    id("passman.compose")
    id("passman.test")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.viewmodel"
    }
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        getByName("commonMain") {
            dependencies {
                api(libs.compose.runtime)
                // Align transitive Compose libs (foundation/ui pulled in by
                // koin-compose-jvm at older versions) with the Compose
                // Multiplatform plugin's version. Without these, the
                // checkComposeLibrariesCompatibility task warns on every build.
                implementation(libs.compose.foundation)
                implementation(libs.compose.ui)

                implementation(libs.kotlinx.datetime)
                implementation(project(":domain"))
                implementation(project(":logging:logger"))
                implementation(project(":presentation:viewvo"))

                implementation(libs.koin.core)
                implementation(libs.koin.compose)
                implementation(libs.koin.composeVM)
                implementation(libs.androidx.lifecycle.viewmodel)
            }
        }
        getByName("commonTest") {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        getByName("androidMain") {
            dependencies {
                implementation(libs.kotlinx.coroutines.android)
            }
        }
        getByName("jvmMain") {
            dependencies {
                implementation(libs.kotlinx.coroutines.swing)
                implementation(project(":logging:logger"))
            }
        }
        getByName("jvmTest") {
            dependencies {
            }
        }
    }
}
