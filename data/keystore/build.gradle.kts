plugins {
    id("passman.kmp.android")
    id("passman.test")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.keystore"
    }
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain = getByName("commonMain") {
            resources.srcDirs("resources")
            dependencies {
                // api, not implementation: KeystoreClient's identity methods take
                // ai.passman.crypto.vault.IdentityStorePassword in their signatures, so every consumer
                // of this module needs :data:crypto on its compile classpath to call them.
                api(project(":data:crypto"))
                implementation(project(path = ":domain"))
                implementation(project(path = ":logging:logger"))
            }
        }

        val jvmAndAndroidMain = create("jvmAndAndroidMain") {
            dependsOn(commonMain)
            dependencies {
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
