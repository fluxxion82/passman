package ai.passman.viewvo.passphrase

sealed interface PassphraseNavigation

data object Back : PassphraseNavigation
data object Copied : PassphraseNavigation
data class ShowMessage(val message: String) : PassphraseNavigation
