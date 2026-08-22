plugins {
    id("passman.kmp.android")
}

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
