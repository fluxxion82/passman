package ai.passman.gradle.plugins

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

/**
 * Opt-in JVM unit-test stack: junit, mockk (+ its agent, from the same version ref),
 * kotlin-test-junit and assertj.
 *
 * Applied to whichever JVM-flavoured test source sets a module actually has. Modules
 * without JVM tests do not apply this plugin and do not pay for it.
 */
class TestPlugin : Plugin<Project> {

    override fun apply(project: Project) = with(project) {
        val libs = extensions.getByType(VersionCatalogsExtension::class.java).named("libs")
        val testJvm = libs.findBundle("test-jvm").get()

        extensions.configure(KotlinMultiplatformExtension::class.java) {
            // configureEach, not findByName: KMP creates test source sets when the module
            // declares its targets, which happens after this plugin is applied. Looking them
            // up eagerly finds nothing and silently adds no dependencies.
            sourceSets.configureEach {
                if (name in JVM_TEST_SOURCE_SETS) {
                    dependencies { implementation(testJvm) }
                }
            }
        }
    }

    private companion object {
        val JVM_TEST_SOURCE_SETS = listOf("jvmTest", "desktopTest", "androidUnitTest")
    }
}
