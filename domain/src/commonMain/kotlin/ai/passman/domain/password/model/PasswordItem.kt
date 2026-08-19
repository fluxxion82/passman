package ai.passman.domain.password.model

sealed class PasswordItem {
    data class AddItem(val entry: PasswordEntry) : PasswordItem()
    data class RemoveItem(val entryId: String) : PasswordItem()
}
