plugins {
    id("passman.kmp")
    id("passman.test")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    applyDefaultHierarchyTemplate()

    // Collection literals are experimental in Kotlin 2.4 (-Xcollection-literals). Scoped to
    // test compilations only, deliberately: production sources stay off experimental syntax.
    targets.configureEach {
        compilations.matching { it.name == "test" }.configureEach {
            compileTaskProvider.configure {
                compilerOptions.freeCompilerArgs.add("-Xcollection-literals")
            }
        }
    }
    // ios()
    // Note: iosSimulatorArm64 target requires that all dependencies have M1 support
    // iosSimulatorArm64()
    js {
        browser()
        binaries.executable()
    }
    jvm()

    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            isStatic = true
        }
    }

    sourceSets {
        getByName("commonMain") {
            dependencies {
                implementation(libs.kotlinx.serialization)
                implementation(libs.kotlinx.coroutines.core)

                implementation(libs.kotlinx.datetime)

                implementation(libs.koin.core)

                implementation(project(":logging:logger"))
            }
        }
        getByName("jsTest") {
            dependencies {
                implementation(libs.kotlin.test.js)
            }
        }
    }
}
