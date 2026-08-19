plugins {
    id("passman.kmp.android")
    alias(libs.plugins.kotlin.serialization)
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.crypto"
    }
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain = getByName("commonMain") {
            resources.srcDirs("resources")
            dependencies {
                // api, not implementation: PasswordHasher.derive exposes KdfParams in its public
                // signature, so every consumer of this module needs :domain on its compile classpath.
                api(project(":domain"))
                implementation(project(":logging:logger"))
            }
        }
        getByName("commonTest") { }

        val jvmAndAndroidMain = create("jvmAndAndroidMain") {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.kotlinx.serialization)
                implementation(libs.bundles.bouncycastle.no.pgp)
            }
        }
        getByName("androidMain") { dependsOn(jvmAndAndroidMain) }
        getByName("jvmMain") { dependsOn(jvmAndAndroidMain) }
        getByName("jvmTest") {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
