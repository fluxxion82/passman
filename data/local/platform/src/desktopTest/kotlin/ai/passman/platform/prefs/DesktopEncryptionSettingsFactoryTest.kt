package ai.passman.platform.prefs

import ai.passman.repo.DesktopProfile
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

/**
 * The desktop master key lives in the platform's secure credential store, and there are systems
 * that have none — a headless Linux box with no D-Bus session is the common one, and the app ships
 * a `.deb`. `StorageProvider.getCredentialStorage` answers that with `null`, which used to be
 * dereferenced straight away: the user got a NullPointerException out of a password manager instead
 * of being told what was missing.
 *
 * Refusing is the right answer — there is nowhere safe to keep the key that protects the prefs — but
 * it has to refuse in a way that names the problem.
 */
class DesktopEncryptionSettingsFactoryTest {

    @Test
    fun `refuses with a clear message when the platform has no secure credential store`() {
        val factory = DesktopEncryptionSettingsFactory(DesktopProfile.Debug, credentialStorage = { null })

        val failure = assertFailsWith<IllegalStateException> { factory.createEncrypted("theme_prefs") }

        val message = failure.message.orEmpty()
        assertTrue(
            "secure credential store" in message,
            "the message must name what is missing, not just fail: $message",
        )
    }
}
