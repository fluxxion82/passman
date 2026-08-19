package ai.passman.domain.initialization.models

sealed class OnboardingStep {
    data class UserData(val step: UserDataStep) : OnboardingStep()
}

enum class UserDataStep {
    ACTIVATE,
    NAME,
    HANDLE,
    BIO,
    ADD_PIC,
    REVIEW_PROFILE,
    FINISHED
}
