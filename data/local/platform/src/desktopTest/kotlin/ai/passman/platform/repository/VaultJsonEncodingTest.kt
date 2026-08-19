package ai.passman.platform.repository

import ai.passman.domain.password.model.PasswordEntry
import kotlin.test.Test
import kotlin.test.assertFalse

/**
 * Obligation 12, pinned against the production codec itself.
 *
 * `PasswordEntryCompatTest` (in `domain`) already pins "a field left at its default is entirely
 * absent from the JSON" for `createdAt`/`activity`, but it has to do so against a `Json {
 * ignoreUnknownKeys = true }` it builds for itself, because `domain` sits below `data/local/platform`
 * and cannot see [VaultJson]. A mirror instance only proves the *mirror* has `encodeDefaults` off; it
 * says nothing about the real one. This test closes that gap by encoding through [VaultJson] directly,
 * so flipping `encodeDefaults = true` on the production instance would fail here even if the mirrored
 * test in `domain` stayed green.
 */
class VaultJsonEncodingTest {

    @Test
    fun `VaultJson omits a zero createdAt and an empty activity list`() {
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

        val encoded = VaultJson.encodeToString(entry)

        assertFalse(encoded.contains("createdAt"), "createdAt at its default must not be written: $encoded")
        assertFalse(encoded.contains("activity"), "an empty activity list must not be written: $encoded")
    }
}
