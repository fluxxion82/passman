package ai.passman.gradle.plugins

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

/**
 * Base for every Kotlin Multiplatform module.
 *
 * Applies the KMP plugin, pins the language level, and adds the two dependencies every
 * module genuinely uses: coroutines in commonMain and kotlin-test in commonTest.
 *
 * It deliberately does not inject anything else. Modules declare what they use.
 */
class KmpPlugin : Plugin<Project> {

    override fun apply(project: Project) = with(project) {
        plugins.apply("org.jetbrains.kotlin.multiplatform")

        val libs = extensions.getByType(VersionCatalogsExtension::class.java).named("libs")
        val coroutinesCore = libs.findLibrary("kotlinx-coroutines-core").get()
        val coroutinesTest = libs.findLibrary("kotlinx-coroutines-test").get()
        val kotlinTest = libs.findLibrary("kotlin-test").get()

        extensions.configure(KotlinMultiplatformExtension::class.java) {
            // Extension-level compilerOptions reach every target. The previous
            // tasks.withType<KotlinCompile> form only configured JVM and Android
            // compilations, so native and JS were compiling unconfigured.
            // languageVersion is deliberately not pinned. It used to be held at 2.1 while
            // the toolchain moved on; leaving it unset tracks the Kotlin version in the
            // catalog, which is what the modules actually compile against.
            compilerOptions {
                optIn.add("kotlin.time.ExperimentalTime")
            }

            sourceSets.getByName(COMMON_MAIN) {
                dependencies { implementation(coroutinesCore) }
            }
            // kotlin-test alone covers multiplatform; kotlin-test-common and
            // kotlin-test-annotations-common have been deprecated since Kotlin 1.5.
            sourceSets.getByName(COMMON_TEST) {
                dependencies {
                    implementation(kotlinTest)
                    implementation(coroutinesTest)
                }
            }
        }

        // jvmTarget only exists on JVM-flavoured compilations, so it stays task-scoped.
        tasks.withType(KotlinCompile::class.java).configureEach {
            compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
        }

        // Register this module's JVM tests with the root aggregator. Lazy because KMP
        // registers jvmTest during its own afterEvaluate.
        afterEvaluate {
            val rootTest = rootProject.tasks.findByName(PROJECT_TEST) ?: return@afterEvaluate
            tasks.findByName("jvmTest")?.let { rootTest.dependsOn(it) }
            tasks.findByName("desktopTest")?.let { rootTest.dependsOn(it) }
        }
    }

    companion object {
        const val COMMON_MAIN = "commonMain"
        const val COMMON_TEST = "commonTest"
        const val PROJECT_TEST = "projectTest"
        const val PROJECT_LINT = "projectLint"
    }
}
