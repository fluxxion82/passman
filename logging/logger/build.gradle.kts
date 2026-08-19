plugins {
    id("passman.kmp")
    id("passman.test")
}

group = "ai.passman.logger"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            isStatic = true
        }
    }
    jvm()
    js {
        browser()
        binaries.executable()
    }

    sourceSets {
        getByName("commonMain") {
            dependencies {
            }
        }

        getByName("commonTest") {
            dependencies { }
        }
        getByName("jvmTest") {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlin.test.junit)
            }
        }
    }
}

