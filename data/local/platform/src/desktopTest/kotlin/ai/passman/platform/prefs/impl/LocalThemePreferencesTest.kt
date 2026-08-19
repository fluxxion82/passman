package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.DesktopEncryptionSettingsFactory
import ai.passman.repo.DesktopProfile
import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.settings.model.ThemeMode
import com.russhwolf.settings.MapSettings
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

class LocalThemePreferencesTest {

    @Test
    fun `missing mode defaults to system`() = runBlocking {
        assertEquals(ThemeMode.System, preferences().getMode())
    }

    @Test
    fun `each theme mode round trips`() = runBlocking {
        val preferences = preferences()

        listOf(ThemeMode.System, ThemeMode.Light, ThemeMode.Dark).forEach { mode ->
            preferences.setMode(mode)

            assertEquals(mode, preferences.getMode())
        }
    }

    @Test
    fun `unrecognised stored mode defaults to system`() = runBlocking {
        val settings = MapSettings().apply { putString("theme_mode", "sepia") }

        assertEquals(ThemeMode.System, preferences(settings).getMode())
    }

    @Test
    fun `theme preference is readable without a user session`() = runBlocking {
        val factory = DesktopEncryptionSettingsFactory(DesktopProfile.Debug)
        factory.createEncrypted("theme_prefs").remove("theme_mode")
        val preferences = LocalThemePreferences(
            encryptedFactory = factory,
            coroutinesContextFacade = UnconfinedFacade,
        )

        assertEquals(ThemeMode.System, preferences.getMode())
    }

    private fun preferences(settings: MapSettings = MapSettings()) = LocalThemePreferences(
        encryptedFactory = object : EncryptionSettingsFactory {
            override fun createEncrypted(name: String) = settings
        },
        coroutinesContextFacade = UnconfinedFacade,
    )

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }
}
