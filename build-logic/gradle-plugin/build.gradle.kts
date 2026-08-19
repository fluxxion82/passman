plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
}

dependencies {
    implementation(libs.android.gradle.plugin)
    implementation(libs.kotlin.gradle.plugin)
}

gradlePlugin {
    plugins {
        register("rootPlugin") {
            id = "passman.root"
            implementationClass = "ai.passman.gradle.plugins.PassmanRootPlugin"
        }
        register("kmpPlugin") {
            id = "passman.kmp"
            implementationClass = "ai.passman.gradle.plugins.KmpPlugin"
        }
        register("kmpAndroidPlugin") {
            id = "passman.kmp.android"
            implementationClass = "ai.passman.gradle.plugins.KmpAndroidPlugin"
        }
        register("composePlugin") {
            id = "passman.compose"
            implementationClass = "ai.passman.gradle.plugins.ComposePlugin"
        }
        register("testPlugin") {
            id = "passman.test"
            implementationClass = "ai.passman.gradle.plugins.TestPlugin"
        }
        register("androidApplicationPlugin") {
            id = "passman.application"
            implementationClass = "ai.passman.gradle.plugins.AndroidApplicationPlugin"
        }
    }
}
