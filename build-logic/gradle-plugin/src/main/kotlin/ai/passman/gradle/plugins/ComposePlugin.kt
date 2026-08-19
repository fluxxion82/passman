package ai.passman.gradle.plugins

import org.gradle.api.Plugin
import org.gradle.api.Project

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
    }
}
