plugins {
    id("passman.kmp.android")
    id("passman.test")
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.pgp"
    }
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain = getByName("commonMain") {
            dependencies {
                implementation(project(":data:crypto"))
                implementation(project(":domain"))
                implementation(project(":logging:logger"))
                implementation(libs.kotlinx.coroutines.core)
            }
        }

        val jvmAndAndroidMain = create("jvmAndAndroidMain") {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.kotlinx.datetime)
                implementation(libs.bundles.bouncycastle)
            }
        }
        getByName("androidMain") { dependsOn(jvmAndAndroidMain) }
        getByName("jvmMain") { dependsOn(jvmAndAndroidMain) }

        getByName("jvmTest") {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
                implementation(libs.javax.inject)
            }
        }
    }
}
