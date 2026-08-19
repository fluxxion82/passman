package ai.passman.gradle.plugins

import ai.passman.gradle.tasks.ProjectLintTask
import ai.passman.gradle.tasks.ProjectTestTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.testing.Test

class PassmanRootPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        with(project) {
            tasks.register("projectLint", ProjectLintTask::class.java)

            val projectTest = tasks.register("projectTest", ProjectTestTask::class.java)
            // Per-module convention plugins (BaseKmmPlugin, LibraryPlugin) wire their own test and
            // lint tasks into these aggregators. Modules applying a stock plugin instead never opt
            // in — apps:desk is plain kotlin("jvm") — so projectTest also depends on every Test
            // task it can find. The provider keeps that lookup lazy, so subproject tasks need not
            // exist when this plugin is applied.
            val everyTestTask = provider {
                subprojects.flatMap { module -> module.tasks.withType(Test::class.java) }
            }
            projectTest.configure { dependsOn(everyTestTask) }
        }
    }
}
