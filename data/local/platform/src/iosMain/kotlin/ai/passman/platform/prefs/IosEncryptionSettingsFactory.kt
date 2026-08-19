package ai.passman.platform.prefs

import com.russhwolf.settings.ExperimentalSettingsImplementation
import com.russhwolf.settings.KeychainSettings
import com.russhwolf.settings.Settings

class IosEncryptionSettingsFactory : EncryptionSettingsFactory {
    @OptIn(ExperimentalSettingsImplementation::class)
    override fun createEncrypted(name: String): Settings = KeychainSettings(service = name)
}
