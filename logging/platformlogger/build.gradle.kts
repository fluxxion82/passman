plugins {
    id("passman.kmp.android")
    id("passman.test")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.logging"
        // src/androidMain/res/values/strings.xml
        androidResources { enable = true }
    }
    jvm()

    sourceSets {
        getByName("commonMain") {
            dependencies {
                implementation(project(":logging:logger"))
            }
        }
    }
}
