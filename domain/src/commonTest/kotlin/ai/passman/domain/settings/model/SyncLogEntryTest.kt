package ai.passman.domain.settings.model

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pins the `outcome: String` decision at the model level, the same way
 * `PasswordEntryCompatTest` pins `EntryActivity.kind`: an enum here would throw on an outcome this
 * build does not recognise instead of round-tripping it, which is exactly the downgrade-safety
 * property this field exists to buy. Obligation 7 (decode half; the render half — an unrecognised
 * outcome falling through to a UI `else` branch — is pinned in `SyncOutcomeLabelsTest`).
 */
class SyncLogEntryTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `an unrecognised outcome decodes and re-encodes verbatim`() {
        val wireJson =
            """{"at":700,"artifact":"passwords","host":"192.0.2.1","outcome":"partial-retry"}"""

        val entry = json.decodeFromString<SyncLogEntry>(wireJson)

        assertEquals("partial-retry", entry.outcome, "an unknown outcome must decode, not throw")
        assertEquals(
            wireJson,
            json.encodeToString(entry),
            "the unrecognised outcome must round-trip byte-for-byte, not collapse to a fallback value",
        )
    }

    @Test
    fun `a legacy row with no deviceName or detail decodes to empty defaults`() {
        val entry = json.decodeFromString<SyncLogEntry>(
            """{"at":700,"artifact":"pgp-keys","host":"192.0.2.1","outcome":"success"}""",
        )

        assertEquals("", entry.deviceName)
        assertEquals("", entry.detail)
    }

    @Test
    fun `every field survives a round trip`() {
        val entry = SyncLogEntry(
            at = 700L,
            artifact = "keystore",
            host = "192.0.2.1",
            deviceName = "laptop",
            outcome = SyncLogEntry.OUTCOME_FAILED,
            detail = "Could not reach 192.0.2.1. The peer's IP may have changed.",
        )

        assertEquals(entry, json.decodeFromString(json.encodeToString(entry)))
    }
}
