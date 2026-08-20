package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.keystore.EnsureDefaultKeystore
import ai.passman.domain.pgp.EnsureDefaultPgpRings
import ai.passman.domain.pgp.ImportDeveloperKey
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull

class LoginUser(
    private val repository: UserRepository,
    private val userPreferences: UserPreferences,
    private val userEventPersistence: UserEventPersistence,
    private val getUserState: GetUserState,
    private val importDeveloperKey: ImportDeveloperKey,
    private val ensureDefaultKeystore: EnsureDefaultKeystore,
    private val ensureDefaultPgpRings: EnsureDefaultPgpRings,
) : Usecase<LoginUser.LoginRequest, Outcome<UserState>> {

    sealed class LoginRequest {
        data class Standard(val email: String, val password: String) : LoginRequest()

        /**
         * No password field, and that absence is the feature: the master password comes out of the
         * account's biometric enrolment, so there is nothing for a caller to pass and no way for
         * this path to quietly fall back to something the user typed.
         */
        data class BioAuth(val email: String) : LoginRequest()
    }

    override suspend fun invoke(param: LoginRequest): Outcome<UserState> {
        return when (
            val outcome = when (param) {
                is LoginRequest.BioAuth -> repository.bioLogin(param.email.trim())
                is LoginRequest.Standard -> repository.login(param.email.trim(), param.password.trim())
            }
        ) {
            is Outcome.Success -> {
                userPreferences.upsert(outcome.value)
                userEventPersistence.update(UserEvent.LoginChanged(outcome.value))
                importBundledDeveloperKey()
                ensureAccountDefaults()

                Outcome.Success(getUserState().also { userPreferences.setUserState(it) })
            }
            is Outcome.Error -> outcome
        }
    }

    /**
     * Post-login work, composed here — AFTER the account is fully bootstrapped, never inside
     * bootstrapAccount's rollback contract. Once per account; a failure is non-fatal and must
     * never block the login that just succeeded, so the whole attempt is capped by
     * [withTimeoutOrNull] — its own deadline returns null instead of throwing, while an OUTER
     * cancellation still surfaces as a CancellationException and is rethrown, not swallowed.
     */
    private suspend fun importBundledDeveloperKey() = nonFatal(DEVELOPER_KEY_IMPORT_TIMEOUT) {
        importDeveloperKey(ImportDeveloperKey.Mode.OncePerAccount)
    }

    /**
     * Same contract as [importBundledDeveloperKey]: once per account, non-fatal, never allowed to
     * hold the login result hostage. Each attempt gets its own cap sized to the work it may do —
     * the common case for both is a preference read that skips in microseconds.
     *
     * The caps bound only each use case's cancellable GUARD phase. Once a use case decides to
     * provision, it commits under NonCancellable and runs to completion — a cancellation landing
     * between "artifact on disk" and "password recorded in the vault" would otherwise orphan the
     * artifact forever (the guards would then flag the account settled). So a pathologically slow
     * keygen means a slow first login, never a destroyed default; the timeout's cancellation
     * surfaces once the committed sequence finishes.
     */
    private suspend fun ensureAccountDefaults() {
        // Creating the starter keystore runs a JCA RSA keygen — slow enough on a low-end device
        // to need real headroom over the developer-key import's 5s.
        nonFatal(DEFAULT_KEYSTORE_TIMEOUT) { ensureDefaultKeystore(Unit) }
        // Re-provisioning default PGP rings generates a 4096-bit PGP RSA key, the slowest keygen
        // in the app — worth a still larger cap, and still bounded.
        nonFatal(DEFAULT_PGP_TIMEOUT) { ensureDefaultPgpRings(EnsureDefaultPgpRings.Request.EnsureProvisioned) }
    }

    private suspend fun nonFatal(timeout: Duration, block: suspend () -> Unit) {
        try {
            withTimeoutOrNull(timeout) { block() }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // The use case / repository already logged the cause; the login outcome stands.
        }
    }

    private companion object {
        /** A stalled volume must not hold the login result hostage. */
        val DEVELOPER_KEY_IMPORT_TIMEOUT = 5.seconds
        val DEFAULT_KEYSTORE_TIMEOUT = 15.seconds
        val DEFAULT_PGP_TIMEOUT = 30.seconds
    }
}
