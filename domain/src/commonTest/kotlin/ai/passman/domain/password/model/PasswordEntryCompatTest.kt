package ai.passman.domain.password.model

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * The vault decoder tolerates unknown keys, so schema growth is safe forward; these tests pin the
 * backward side — rows written before [PasswordEntry.totpSeed], [PasswordEntry.customFields],
 * [PasswordEntry.createdAt] and [PasswordEntry.activity] existed must decode to the empty defaults,
 * and the new fields must survive a round trip.
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

    /**
     * Obligation 1 (decode half; the backfill half — deriving `createdAt` from `dateCreated` — is
     * `PasswordEntryIdentity.stabilize`'s job and is pinned in `EntryIdentityTest`).
     */
    @Test
    fun `a legacy row decodes with a zero createdAt and no activity`() {
        val entry = json.decodeFromString<PasswordEntry>(
            """{"id":"1","entryName":"gmail","username":"mia","password":"pw","website":"","notes":"","dateCreated":900,"uuid":"u-1"}""",
        )
        assertEquals(0L, entry.createdAt)
        assertEquals(emptyList(), entry.activity)
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

    /** Obligation 2. */
    @Test
    fun `createdAt and activity survive a round trip`() {
        val entry = PasswordEntry(
            id = "1",
            entryName = "gmail",
            username = "mia",
            password = "pw",
            website = "https://mail.google.com",
            notes = "",
            dateCreated = 900,
            uuid = "u-1",
            createdAt = 500,
            activity = listOf(
                EntryActivity(at = 500, kind = EntryActivity.KIND_CREATED),
                EntryActivity(at = 900, kind = EntryActivity.KIND_EDITED, device = "desktop-1"),
            ),
        )
        val decoded = json.decodeFromString<PasswordEntry>(json.encodeToString(entry))
        assertEquals(entry, decoded)
        assertEquals(500L, decoded.createdAt)
        assertEquals(
            listOf(EntryActivity(500, EntryActivity.KIND_CREATED), EntryActivity(900, EntryActivity.KIND_EDITED, "desktop-1")),
            decoded.activity,
        )
    }

    /**
     * Obligation 3 (decode/round-trip half; "survives a merge" is pinned where the merge lives, in
     * `EntryIdentityTest`). This is the test that pins the `kind: String` decision at the model level:
     * an enum here would throw on the unrecognised value instead of round-tripping it.
     */
    @Test
    fun `an entry activity with an unrecognised kind decodes and re-encodes verbatim`() {
        val wireJson =
            """{"id":"1","entryName":"gmail","username":"mia","password":"pw","website":"","notes":"",""" +
                """"dateCreated":900,"uuid":"u-1","createdAt":500,"activity":[{"at":700,"kind":"totp-viewed"}]}"""

        val entry = json.decodeFromString<PasswordEntry>(wireJson)

        assertEquals("totp-viewed", entry.activity.single().kind, "an unknown kind must decode, not throw")
        assertEquals(
            wireJson,
            json.encodeToString(entry),
            "the unrecognised kind must round-trip byte-for-byte, not collapse to a fallback value",
        )
    }

    /**
     * The tombstone's forward-compatibility claim, at the model level.
     *
     * A deletion is an [EntryActivity.KIND_DELETED] record rather than a `deleted: Boolean = false`
     * field on [PasswordEntry] precisely so a peer that does not know the kind cannot destroy it. A
     * new boolean would be stripped by that peer's re-encode — `encodeDefaults` is off, so a field it
     * cannot see is a field it writes back at its default — and the entry would sync home looking
     * alive. An unrecognised *kind* inside a field the peer does know round-trips byte for byte, so
     * the tombstone crosses a build that has never heard of it untouched.
     *
     * Deliberately asserted against the `"deleted"` wire value and not against the constant on the
     * left of the comparison: what has to hold is the bytes, and a rename of the constant that
     * changed them would be a silent wire break.
     */
    @Test
    fun `a deletion tombstone round-trips through a build that does not know the kind`() {
        val wireJson =
            """{"id":"1","entryName":"gmail","username":"mia","password":"pw","website":"","notes":"",""" +
                """"dateCreated":900,"uuid":"u-1","createdAt":500,"activity":[{"at":700,"kind":"deleted"}]}"""

        val entry = json.decodeFromString<PasswordEntry>(wireJson)

        assertEquals("deleted", EntryActivity.KIND_DELETED, "the tombstone's wire value is format, not code style")
        assertEquals(
            listOf(EntryActivity(700, EntryActivity.KIND_DELETED)),
            entry.activity,
            "a build that treats the kind as an opaque string still decodes the tombstone",
        )
        assertEquals(
            wireJson,
            json.encodeToString(entry),
            "and re-encodes it verbatim, so a peer one build behind cannot resurrect the entry by saving it",
        )
    }

    /**
     * Obligation 12. `encodeDefaults` is off (`VaultJson.kt`'s production `Json` instance, mirrored
     * here), so a field left at its default must be entirely absent from the JSON — not written as
     * `"createdAt":0` or `"activity":[]` — or every existing vault would grow the moment it is
     * re-encoded by a build that knows these fields.
     */
    @Test
    fun `an empty activity list and a zero createdAt are absent from the encoded json`() {
        val entry = PasswordEntry(
            id = "1",
            entryName = "gmail",
            username = "mia",
            password = "pw",
            website = "",
            notes = "",
            dateCreated = 900,
            uuid = "u-1",
        )

        val encoded = json.encodeToString(entry)

        assertFalse(encoded.contains("createdAt"), "createdAt at its default must not be written: $encoded")
        assertFalse(encoded.contains("activity"), "an empty activity list must not be written: $encoded")
    }

    @Test
    fun `custom field secrecy defaults to visible for rows written before the flag`() {
        val field = json.decodeFromString<CustomField>("""{"label":"seat","value":"12F"}""")
        assertEquals(false, field.secret)
    }
}
