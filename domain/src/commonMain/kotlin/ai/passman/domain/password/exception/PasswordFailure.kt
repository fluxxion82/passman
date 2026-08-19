package ai.passman.domain.password.exception

import ai.passman.domain.exception.Failure

sealed class PasswordFailure : Failure.FeatureFailure() {
    /**
     * The vault could not be opened or decoded — deliberately NOT the same answer as an empty
     * vault. [ai.passman.domain.password.repository.PasswordRepository.getPasswordEntries]
     * flattens both to an empty list for display; callers whose decision differs (the
     * default-artifact guards must not provision on a failed read) use
     * [ai.passman.domain.password.repository.PasswordRepository.listPasswordEntries] and get this.
     */
    data object VaultUnreadable : PasswordFailure()
}
