package ai.passman.viewvo.navigation

sealed interface SettingsNavigation {
    data class Transfer(val isReceiving: Boolean) : SettingsNavigation
}
