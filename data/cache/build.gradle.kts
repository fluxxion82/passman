plugins {
    id("passman.kmp.android")
}

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.cache"
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
                implementation(libs.koin.core)
            }
        }

        val jvmAndAndroidMain = create("jvmAndAndroidMain") {
            dependsOn(commonMain)
        }
        getByName("androidMain") { dependsOn(jvmAndAndroidMain) }
        getByName("jvmMain") { dependsOn(jvmAndAndroidMain) }
    }
}
