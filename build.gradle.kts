plugins {
    id("passman.root")
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.compose) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}

// One version for the whole repo, from gradle.properties. Modules used to each restate
// `group`/`version` as literals, which silently overrode this block and left the properties
// reaching nothing. Nothing consumes a module's coordinates — there is no publish pipeline, modules
// are wired by project include — so the values only have to be right for the two apps, which read
// them for packageVersion (desk) and versionName (droid). :k2k is a submodule and keeps its own.
subprojects {
    val GROUP: String by project
    val VERSION_NAME: String by project
    group = GROUP
    version = VERSION_NAME
}
