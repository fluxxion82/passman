plugins {
    id("passman.kmp.android")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.viewvo"
    }
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        getByName("commonMain") {
            dependencies {
                implementation(project(":domain"))
                implementation(project(":logging:logger"))
                implementation(libs.kotlinx.datetime)
            }
        }
    }
}
