package ai.passman.di

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
    fun `prod build variant registers no logging sink`() {
        // The prod variant must bind no Logger at all: FileLogger creates its output file during
        // construction, and even warning and error messages can carry account names, vault paths,
        // or provider text. This is checked against the source rather than the Koin graph because
        // only one variant is on the classpath at a time — under the default debug variant a
        // graph-level assertion would pass without ever seeing the prod bindings.
        val prodModule = repositoryRoot()
            .resolve("apps/desk/src/prod/kotlin/ai/passman/di/BuildVariantModule.kt")
        assertTrue(Files.exists(prodModule), "missing $prodModule")

        val bindings = Files.readAllLines(prodModule, StandardCharsets.UTF_8)
            .mapIndexedNotNull { index, line ->
                "${index + 1}: $line".takeIf {
                    Regex("""(?m)^\s*single.*""").containsMatchIn(line) &&
                        Regex("""Logger|bind Logger::class""").containsMatchIn(line)
                }
            }
        assertEquals(emptyList(), bindings, "prod variant must not register a Logger")
    }

    @Test
    fun `debug build variant does register logging sinks`() {
        // The counterpart: if someone strips the debug bindings, developer builds go silent and
        // the test above would still pass. Pin both ends.
        val debugModule = repositoryRoot()
            .resolve("apps/desk/src/debug/kotlin/ai/passman/di/BuildVariantModule.kt")
        // Ignore imports — they mention both loggers even if every binding is deleted.
        val body = Files.readAllLines(debugModule, StandardCharsets.UTF_8)
            .filterNot { it.trimStart().startsWith("import ") }
            .joinToString("\n")
        assertTrue(
            Regex("""single\s*\{\s*JvmLogger\s*\}\s*bind\s+Logger::class""").containsMatchIn(body),
            "debug variant should bind the console logger",
        )
        assertTrue(
            Regex("""FileLogger\s*\(""").containsMatchIn(body),
            "debug variant should bind the file logger",
        )
    }

    /** Walks up from the module directory to the repository root, identified by the included build. */
    private fun repositoryRoot(): Path = generateSequence(Path.of("").toAbsolutePath()) { it.parent }
        .first { it.resolve("build-logic").toFile().isDirectory && it.resolve("settings.gradle.kts").toFile().isFile }
}
