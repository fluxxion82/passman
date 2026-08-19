package ai.passman.gradle.plugins

import com.android.build.api.dsl.KotlinMultiplatformAndroidLibraryExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.plugins.ExtensionAware
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

/**
 * Android target for a KMP module.
 *
 * Uses AGP's KMP library plugin rather than `com.android.library` + `androidTarget()`.
 * The latter is the legacy integration and is not supported by AGP 9.
 *
 * Supplies compileSdk/minSdk from the catalog so modules stop repeating them. Namespace
 * stays in the module, since it is necessarily per-module.
 */
class KmpAndroidPlugin : Plugin<Project> {

    override fun apply(project: Project) = with(project) {
        plugins.apply(KmpPlugin::class.java)
        plugins.apply("com.android.kotlin.multiplatform.library")

        val libs = extensions.getByType(VersionCatalogsExtension::class.java).named("libs")
        val compileSdkVersion = libs.findVersion("compileSdk").get().requiredVersion.toInt()
        val minSdkVersion = libs.findVersion("minSdk").get().requiredVersion.toInt()

        val kmp = extensions.getByType(KotlinMultiplatformExtension::class.java)
        (kmp as ExtensionAware).extensions.configure(
            KotlinMultiplatformAndroidLibraryExtension::class.java,
        ) {
            compileSdk = compileSdkVersion
            minSdk = minSdkVersion
        }

        // Register Android variants with the root aggregators.
        //
        // Note on lint: AGP 8.13's KMP library plugin registers no runnable lint task for
        // these modules — only androidCompileLintChecks and the lint-jar plumbing. So
        // projectLint aggregates nothing here, and in passmanShared it has no members at
        // all, since that build has no application module. Both names are checked so this
        // starts working on its own if AGP begins registering one.
        afterEvaluate {
            val root = rootProject.tasks
            root.findByName(KmpPlugin.PROJECT_LINT)?.let { lint ->
                val lintTask = tasks.findByName("lintDebug") ?: tasks.findByName("lint")
                lintTask?.let { lint.dependsOn(it) }
            }
            root.findByName(KmpPlugin.PROJECT_TEST)?.let { test ->
                ANDROID_UNIT_TEST_TASKS.forEach { name ->
                    tasks.findByName(name)?.let { test.dependsOn(it) }
                }
            }
        }
    }

    private companion object {
        val ANDROID_UNIT_TEST_TASKS = listOf(
            "testDebugUnitTest",
            "testAndroidDebugUnitTest",
            "androidHostTest",
            "testAndroidHostTest",
        )
    }
}
