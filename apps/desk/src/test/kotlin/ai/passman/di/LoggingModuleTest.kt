package ai.passman.di

import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.identification.model.DeviceInfo
import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import ai.passman.logging.Logger
import ai.passman.repo.Platform
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.dsl.module
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LoggingModuleTest {

    @Test
    fun `release source contains no direct diagnostic output`() {
        val repository = repositoryRoot()
        val sourceRoots = listOf(
            repository.resolve("apps/desk/src/main"),
            repository.resolve("apps/droid/src/main"),
            repository.resolve("domain"),
            repository.resolve("data"),
            repository.resolve("presentation"),
            repository.resolve("logging"),
            repository.resolve("k2k/k2k/src"),
        )
        val allowedDebugSink = repository.resolve(
            "logging/platformlogger/src/jvmMain/kotlin/ai/passman/logging/jvm/JvmLogger.kt",
        )
        val directOutput = Regex("""(?m)^\s*(?:println\(|.*\.printStackTrace\(|System\.(?:out|err)\.)""")

        val violations = sourceRoots.flatMap { sourceRoot ->
            Files.walk(sourceRoot).use { paths ->
                paths
                    .filter { source ->
                        source.toString().endsWith(".kt") &&
                            source.toString().contains("${java.io.File.separator}src${java.io.File.separator}") &&
                            !source.toString().contains(
                                Regex(
                                    "${java.io.File.separator}src${java.io.File.separator}" +
                                        "(?:test|commonTest|jvmTest|desktopTest|androidTest|iosTest|jsTest)" +
                                        java.io.File.separator,
                                ),
                            ) &&
                            source != allowedDebugSink
                    }
                    .map { source ->
                        val outputLines = Files.readAllLines(source, StandardCharsets.UTF_8)
                            .mapIndexedNotNull { index, line ->
                                (index + 1).takeIf { directOutput.containsMatchIn(line) }
                            }
                        source to outputLines
                    }
                    .filter { (_, outputLines) -> outputLines.isNotEmpty() }
                    .toList()
            }
        }

        assertTrue(
            violations.isEmpty(),
            violations.joinToString("\n") { (source, lines) -> "$source:${lines.joinToString()}" },
        )
    }

    @Test
    fun `production profile registers no logging sinks`() {
        val previousProfile = System.getProperty("passman.profile")
        val dataDirectory = Files.createTempDirectory("passman-release-logging-test")
        System.clearProperty("passman.profile")

        try {
            val app = startKoin {
                modules(
                    module {
                        single<Platform> {
                            object : Platform() {
                                override fun getLocalPath() = dataDirectory.toString()
                            }
                        }
                        single {
                            AppInformation(
                                version = Version("test", "1", ""),
                                versionCode = 1,
                                id = "ai.passman.test",
                                environment = Environment.PROD,
                                debug = false,
                                userHomeDir = dataDirectory.toString(),
                            )
                        }
                        single { DeviceInfo("test", "test", 1) }
                        single<CoroutineScopeFacade> {
                            object : CoroutineScopeFacade {
                                override val globalScope = CoroutineScope(Dispatchers.Unconfined)
                                override var transferScope = CoroutineScope(Dispatchers.Unconfined)
                            }
                        }
                    },
                    loggingModule,
                )
            }

            assertEquals(emptyList(), app.koin.getAll<Logger>())
        } finally {
            stopKoin()
            if (previousProfile == null) {
                System.clearProperty("passman.profile")
            } else {
                System.setProperty("passman.profile", previousProfile)
            }
            dataDirectory.toFile().deleteRecursively()
        }
    }

    /** Walks up from the module directory to the repository root, identified by the included build. */
    private fun repositoryRoot(): Path = generateSequence(Path.of("").toAbsolutePath()) { it.parent }
        .first { it.resolve("build-logic").toFile().isDirectory && it.resolve("settings.gradle.kts").toFile().isFile }
}
