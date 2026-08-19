package ai.passman.viewvo.home

sealed class HomeNavigation {
    data object PasswordManagement : HomeNavigation()
    data object KeystoreTools : HomeNavigation()
    data object PgpTools : HomeNavigation()
    data object AddPass : HomeNavigation()
    data object AddPgpKey : HomeNavigation()
    data object AddKeystore : HomeNavigation()
    data object Settings : HomeNavigation()
    data object Logout : HomeNavigation()
}
