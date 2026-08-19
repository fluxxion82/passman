plugins {
    id("passman.kmp.android")
    alias(libs.plugins.kotlin.serialization)
}

group = "ai.passman"
version = "0.0.1"

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.repo"
        packaging {
            resources {
                excludes.add("META-INF/INDEX.LIST")
                excludes.add("META-INF/io.netty.versions.properties")
                excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
            }
        }
    }
    jvm("desktop")
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain = getByName("commonMain") {
            dependencies {
                implementation(project(":data:crypto"))
                implementation(project(":domain"))
                implementation(project(":logging:logger"))
                implementation(project(":k2k"))
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)
                implementation(libs.kotlinx.serialization)
                implementation(libs.koin.core)
            }
        }

        getByName("commonTest") {
            dependencies {

            }
        }

        val jvmAndAndroidMain = create("jvmAndAndroidMain") {
            dependencies {
                dependsOn(commonMain)
                implementation(project(":data:pgp"))
                implementation(project(":data:keystore"))
                implementation(project(":data:cache"))

                implementation(libs.bundles.bouncycastle)
            }
        }

        getByName("androidMain") {
            dependencies {
                dependsOn(jvmAndAndroidMain)
                implementation(libs.koin.android)
            }
        }

        getByName("desktopMain") {
            dependencies {
                dependsOn(jvmAndAndroidMain)

            }
        }

        getByName("desktopTest") {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}
