package ai.passman.domain.user.models

sealed class UserEvent {
    data class LoginChanged(val user: AppUser) : UserEvent()
}
