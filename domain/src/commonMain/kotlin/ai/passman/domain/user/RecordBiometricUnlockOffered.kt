package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences

/**
 * Spend the signed-in account's one enrolment offer without making one.
 *
 * The signup form asks its own question, with a checkbox, before the account exists. An account
 * that was shown that checkbox and left it unticked has answered — and [OfferBiometricUnlock] would
 * otherwise ask the same question again, as a modal, at the very next login. That is the nagging
 * the flag exists to prevent, so signup spends the offer on its own behalf.
 *
 * Only for the *declined* case. A ticked box whose prompt was cancelled or failed leaves the offer
 * unspent on purpose: that user said yes, and the login dialog is then their retry rather than a
 * repetition.
 *
 * The account is resolved here rather than passed in, for the same reason it is in
 * [SetBiometricUnlock]: a name from the caller is one typo away from silencing a different account.
 */
class RecordBiometricUnlockOffered(
    private val repository: BiometricUnlockRepository,
    private val userPreferences: UserPreferences,
) : Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) {
        val username = (userPreferences.getUser() as? AppUser.LoggedIn)?.userName ?: return
        repository.recordEnrolmentOffered(username)
    }
}
