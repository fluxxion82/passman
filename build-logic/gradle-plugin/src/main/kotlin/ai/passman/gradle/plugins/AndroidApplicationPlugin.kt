package ai.passman.gradle.plugins

import com.android.build.api.dsl.ApplicationExtension
import java.io.File
import org.gradle.api.JavaVersion
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalogsExtension

/**
 * Android application module.
 *
 * Uses the modern `ApplicationExtension` DSL rather than the legacy `AppExtension` /
 * `lintOptions` / `compileSdkVersion(int)` APIs, which AGP 9 removes.
 *
 * Supplies SDK levels from the catalog and applies any `.pro` files found in the module's
 * `proguard/` directory. It injects no dependencies — the app declares its own.
 */
class AndroidApplicationPlugin : Plugin<Project> {

    override fun apply(project: Project) = with(project) {
        // AGP 9 has built-in Kotlin support and rejects org.jetbrains.kotlin.android.
        // kotlin-parcelize is not applied either: nothing in either repo uses @Parcelize
        // or Parcelable. The old BaseAndroidPlugin applied both to every Android module.
        plugins.apply("com.android.application")

        val libs = extensions.getByType(VersionCatalogsExtension::class.java).named("libs")
        val compileSdkVersion = libs.findVersion("compileSdk").get().requiredVersion.toInt()
        val minSdkVersion = libs.findVersion("minSdk").get().requiredVersion.toInt()
        val targetSdkVersion = libs.findVersion("targetSdk").get().requiredVersion.toInt()

        extensions.configure(ApplicationExtension::class.java) {
            compileSdk = compileSdkVersion
            defaultConfig {
                minSdk = minSdkVersion
                targetSdk = targetSdkVersion
            }

            compileOptions {
                sourceCompatibility = JavaVersion.VERSION_17
                targetCompatibility = JavaVersion.VERSION_17
            }

            val baselineFile = File(projectDir, "androidlint-baseline.xml")
            if (baselineFile.exists() || hasProperty("refreshBaseline")) {
                lint { baseline = baselineFile }
            }

            val proFiles = File(projectDir, "proguard")
                .listFiles()
                ?.filter { it.isFile && it.extension == "pro" }
                .orEmpty()
            if (proFiles.isEmpty()) {
                logger.info("No proguard files in {}/proguard", projectDir)
            } else {
                buildTypes.configureEach { proguardFiles(*proFiles.toTypedArray()) }
            }
        }

        afterEvaluate {
            val root = rootProject.tasks
            root.findByName(KmpPlugin.PROJECT_LINT)?.let { lint ->
                tasks.findByName("lintDebug")?.let { lint.dependsOn(it) }
            }
            root.findByName(KmpPlugin.PROJECT_TEST)?.let { test ->
                tasks.findByName("testDebugUnitTest")?.let { test.dependsOn(it) }
            }
        }
    }
}
