package ai.passman.domain.password.model

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The vault decoder tolerates unknown keys, so schema growth is safe forward; these tests pin the
 * backward side — rows written before [PasswordEntry.totpSeed] and [PasswordEntry.customFields]
 * existed must decode to the empty defaults, and the new fields must survive a round trip.
 */
class PasswordEntryCompatTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `a legacy row decodes with no totp seed and no custom fields`() {
        val entry = json.decodeFromString<PasswordEntry>(
            """{"id":"1","entryName":"gmail","username":"mia","password":"pw","website":"","notes":"","dateCreated":900,"uuid":"u-1"}""",
        )
        assertEquals("", entry.totpSeed)
        assertEquals(emptyList(), entry.customFields)
    }

    @Test
    fun `totp seed and custom fields survive a round trip`() {
        val entry = PasswordEntry(
            id = "1",
            entryName = "gmail",
            username = "mia",
            password = "pw",
            website = "https://mail.google.com",
            notes = "",
            dateCreated = 900,
            uuid = "u-1",
            totpSeed = "JBSWY3DPEHPK3PXP",
            customFields = listOf(
                CustomField(label = "recovery email", value = "backup@example.com"),
                CustomField(label = "pin", value = "1234", secret = true),
            ),
        )
        assertEquals(entry, json.decodeFromString(json.encodeToString(entry)))
    }

    @Test
    fun `custom field secrecy defaults to visible for rows written before the flag`() {
        val field = json.decodeFromString<CustomField>("""{"label":"seat","value":"12F"}""")
        assertEquals(false, field.secret)
    }
}
