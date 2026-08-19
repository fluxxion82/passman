plugins {
    id("passman.root")
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.compose) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}

val libraryVersion = project.property("LIBRARY_VERSION") as String

subprojects {
    val GROUP: String by project
    group = GROUP
    version = libraryVersion
}
