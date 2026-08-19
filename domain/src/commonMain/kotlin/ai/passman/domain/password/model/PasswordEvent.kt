package ai.passman.domain.password.model

sealed class PasswordEvent {
    object Created : PasswordEvent()
    object Updated : PasswordEvent()

    /** [uuid] is [PasswordEntry.uuid] — the stable identity, never the display ordinal. */
    data class Deleted(val uuid: String) : PasswordEvent()
}
