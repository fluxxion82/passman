package ai.passman.domain.initialization.models

sealed class InitialAppState {
    // object ObsoleteVersionInstalled : InitialAppState()
}

sealed class UserState : InitialAppState() {
    data object Anonymous : UserState()
    data object LoggedIn : UserState()
    data class PendingActive(
        val step: OnboardingStep =
            OnboardingStep.UserData(UserDataStep.ACTIVATE)
    ) : UserState()
}
