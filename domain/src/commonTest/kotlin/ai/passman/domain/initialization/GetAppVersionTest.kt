package ai.passman.domain.initialization

import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

/**
 * The string under the settings list is how a tester says *which* build they are looking at, so the
 * build number belongs in it: two Android builds can, and routinely do, share a version name.
 */
class GetAppVersionTest {

    @Test
    fun `the version name carries the build number beside it`() = runTest {
        val useCase = GetAppVersion(appInformation(name = "1.0.0", code = 6, debug = false))

        assertEquals("v1.0.0 (6)", useCase(Unit))
    }

    @Test
    fun `a debug build says so`() = runTest {
        val useCase = GetAppVersion(appInformation(name = "1.0.3", code = 1, debug = true))

        assertEquals("v1.0.3 (1) · debug", useCase(Unit))
    }

    @Test
    fun `a build with no version name still names its build number`() = runTest {
        val useCase = GetAppVersion(appInformation(name = "", code = 12, debug = false))

        assertEquals("(12)", useCase(Unit))
    }

    private fun appInformation(name: String, code: Int, debug: Boolean) = AppInformation(
        version = Version(name = name, build = "0", additionalInfo = ""),
        versionCode = code,
        id = "ai.passman",
        environment = if (debug) Environment.SANDBOX else Environment.PROD,
        debug = debug,
        userHomeDir = "/tmp",
    )
}
