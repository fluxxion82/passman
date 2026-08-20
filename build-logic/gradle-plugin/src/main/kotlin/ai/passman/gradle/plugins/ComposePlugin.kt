package ai.passman.gradle.plugins

import com.android.build.api.dsl.KotlinMultiplatformAndroidLibraryExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.ExtensionAware
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

/**
 * Compose Multiplatform for a KMP module.
 *
 * Only applies the two plugins, which must stay version-aligned. Compose artifacts are
 * declared per module via the `compose.*` accessors, because the modules genuinely need
 * different subsets.
 */
class ComposePlugin : Plugin<Project> {

    override fun apply(project: Project) {
        project.plugins.apply("org.jetbrains.compose")
        project.plugins.apply("org.jetbrains.kotlin.plugin.compose")

        // Compose resources reach an Android app through the library's *assets*, and AGP's KMP
        // library plugin leaves Android resource processing OFF by default. With it off the
        // variant exposes no assets source at all, so Compose's own
        // `copyAndroidMainComposeResourcesToAndroidAssets` is never given an output directory and
        // never runs: the resources are built for desktop and iOS, silently absent on Android.
        //
        // That is not a loud failure. It cost this project a font — every M3 text style resolves
        // through `Font(Res.font.inter_regular)`, so desktop rendered Inter while Android fell
        // back to the system face, with nothing in any build log to say so. Enabling it here
        // rather than per module means the next module to add a drawable or a string does not
        // rediscover it.
        //
        // withId rather than a direct call: plugin application order between `passman.compose` and
        // `passman.kmp.android` is up to the module, and this must not depend on it.
        project.plugins.withId("com.android.kotlin.multiplatform.library") {
            val kmp = project.extensions.getByType(KotlinMultiplatformExtension::class.java)
            (kmp as ExtensionAware).extensions
                .configure(KotlinMultiplatformAndroidLibraryExtension::class.java) {
                    androidResources.enable = true
                }
        }
    }
}
