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
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

class SignUpUser(
    private val repository: UserRepository,
    private val userPreferences: UserPreferences,
    private val userEventPersistence: UserEventPersistence,
    private val getUserState: GetUserState,
    private val importDeveloperKey: ImportDeveloperKey,
    private val ensureDefaultKeystore: EnsureDefaultKeystore,
    private val ensureDefaultPgpRings: EnsureDefaultPgpRings,
    private val generatePassword: GeneratePassword,
) : Usecase<SignUpUser.SignUpRequest, Outcome<UserState>> {
    /**
     * Only one way to sign up. The biometric variant is gone: biometric unlock stores a copy of a
     * master password under a hardware key, and doing that from inside `bootstrapAccount` would put
     * a system prompt — which the user can sit on, or dismiss — in the middle of a rollback
     * contract that has to run to completion. Enrolment is a settings action on an account that
     * already exists.
     */
    sealed class SignUpRequest {
        data class Standard(val email: String, val password: String) : SignUpRequest()
    }
    override suspend fun invoke(param: SignUpRequest): Outcome<UserState> {
        // Generated HERE, in signup scope, because the two places that need it cannot reach each
        // other: the repository seals the rings with it inside bootstrapAccount (before the vault
        // session binds), and the vault entry recording it can only be written after signup
        // returns success.
        val pgpPassphrase = generatePassword(GeneratePassword.PROVISIONED_SECRET)
        return when (
            val outcome = when (param) {
                is SignUpRequest.Standard -> repository.signup(
                    username = param.email.trim(),
                    password = param.password.trim(),
                    pgpPassphrase = pgpPassphrase,
                )
            }
        ) {
            is Outcome.Success -> {
                userPreferences.upsert(outcome.value)
                userEventPersistence.update(UserEvent.LoginChanged(outcome.value))
                // The three provisioning steps are independent and individually non-fatal, so they
                // run concurrently. The ring record still starts immediately — until it lands, the
                // ring passphrase exists only in this frame, and losing it makes the fresh rings
                // unrecoverable (the use case rolls them back in that case, so the next login
                // re-provisions). The starter keystore's keygen and PKCS#12 KDF work no longer
                // queues behind either of the others; concurrent vault writes are safe because the
                // publish is compare-and-swap with re-apply, not last-write-wins.
                coroutineScope {
                    launch { recordFreshPgpRings(pgpPassphrase) }
                    launch { importBundledDeveloperKey() }
                    launch { ensureStarterKeystore() }
                }
                Outcome.Success(getUserState().also { userPreferences.setUserState(it) })
            }
            is Outcome.Error -> outcome //UserState.Anonymous
        }
    }

    /**
     * Post-signup work, composed here — AFTER the repository's bootstrapAccount has fully
     * succeeded, never inside its rollback contract. A failure is non-fatal and must never
     * fail the signup that just succeeded, so the whole attempt is capped by
     * [withTimeoutOrNull] — its own deadline returns null instead of throwing, while an OUTER
     * cancellation still surfaces as a CancellationException and is rethrown, not swallowed.
     */
    private suspend fun importBundledDeveloperKey() = nonFatal(DEVELOPER_KEY_IMPORT_TIMEOUT) {
        importDeveloperKey(ImportDeveloperKey.Mode.OncePerAccount)
    }

    /**
     * Two encrypted vault publishes on a cold device can be slow, hence the real cap. Like every
     * ensure cap here, it only bounds entry into the use case's committed phase: the record (and
     * its rollback-on-failure) runs under NonCancellable inside the use case, so a timeout can
     * never strand fresh rings whose passphrase was lost mid-write.
     */
    private suspend fun recordFreshPgpRings(passphrase: String) = nonFatal(PGP_RECORD_TIMEOUT) {
        ensureDefaultPgpRings(EnsureDefaultPgpRings.Request.RecordFreshRings(passphrase))
    }

    /**
     * Creating the starter keystore runs a JCA RSA keygen — slow enough on a low-end device to
     * need real headroom over the developer-key import's 5s. The cap bounds only the use case's
     * cancellable guard phase; once past the guards it commits under NonCancellable and runs to
     * completion (a slow signup beats an orphaned keystore).
     */
    private suspend fun ensureStarterKeystore() = nonFatal(DEFAULT_KEYSTORE_TIMEOUT) {
        ensureDefaultKeystore(Unit)
    }

    private suspend fun nonFatal(timeout: Duration, block: suspend () -> Unit) {
        try {
            withTimeoutOrNull(timeout) { block() }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // The use case / repository already logged the cause; the signup outcome stands.
        }
    }

    private companion object {
        /** A stalled volume must not hold the signup result hostage. */
        val DEVELOPER_KEY_IMPORT_TIMEOUT = 5.seconds
        val PGP_RECORD_TIMEOUT = 15.seconds
        val DEFAULT_KEYSTORE_TIMEOUT = 15.seconds
    }
}
