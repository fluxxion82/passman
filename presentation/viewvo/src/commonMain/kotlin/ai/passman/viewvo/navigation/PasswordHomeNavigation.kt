package ai.passman.viewvo.navigation

sealed interface PasswordHomeNavigation

/** [passUuid] is `PasswordEntry.uuid` — the stable identity, never the display ordinal. */
data class PassDetails(val passUuid: String) : PasswordHomeNavigation
