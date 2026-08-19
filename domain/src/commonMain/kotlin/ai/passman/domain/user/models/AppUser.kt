package ai.passman.domain.user.models

sealed class AppUser {
    object Anonymous : AppUser()
    data class LoggedIn(
        val userName: String,
        val password: Password,
    ) : AppUser()

    data class AccountCreated(
        val userName: String,
        val password: Password,
    ) : AppUser()
}
