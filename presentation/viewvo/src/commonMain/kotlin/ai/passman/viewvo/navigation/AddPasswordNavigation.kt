package ai.passman.viewvo.navigation

sealed interface AddPasswordNavigation

data class InvalidEntry(val message: String) : AddPasswordNavigation
