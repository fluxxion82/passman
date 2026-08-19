plugins {
    id("passman.kmp")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()

    listOf(iosArm64(), iosSimulatorArm64()).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "PassmanShared"
            isStatic = true
            export(project(":domain"))
            export(project(":data:crypto"))
            export(project(":presentation:viewmodel"))
            export(project(":presentation:viewvo"))
            export(project(":presentation:screens"))
        }
    }

    sourceSets {
        getByName("commonMain") {
            dependencies {
                api(project(":domain"))
                api(project(":data:crypto"))
                api(project(":presentation:viewmodel"))
                api(project(":presentation:viewvo"))
                api(project(":presentation:screens"))

                implementation(project(":data:pgp"))
                implementation(project(":data:keystore"))
                implementation(project(":data:cache"))
                implementation(project(":presentation:design"))
                implementation(project(":logging:logger"))

                implementation(libs.koin.core)
            }
        }
    }
}
