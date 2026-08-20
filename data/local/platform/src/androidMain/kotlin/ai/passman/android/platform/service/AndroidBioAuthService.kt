package ai.passman.android.platform.service

import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.platform.service.BioAuthFailure
import ai.passman.platform.service.BioAuthService
import ai.passman.platform.service.WrappedSecret
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/**
 * AES-256-GCM in the AndroidKeyStore, one key per account, unusable without a fresh biometric.
 *
 * ## The key
 *
 * `setUserAuthenticationRequired(true)` plus `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`
 * — a **zero** timeout, which means per-operation rather than per-time-window. That distinction is
 * the point of the whole class: a time-window key can be used by any code that runs inside the
 * window, whereas a per-operation key can only be used through a `Cipher` the system itself
 * authorised inside `onAuthenticationSucceeded`. There is no way to reach it by convincing the app
 * that a prompt succeeded.
 *
 * `setInvalidatedByBiometricEnrollment(true)` is the other half. Registering a new fingerprint
 * destroys the key, so somebody who takes an unlocked phone and adds their own finger inherits an
 * unusable key rather than the vault. It costs the honest user a re-enrolment when they add a
 * finger, which is the correct trade.
 *
 * StrongBox is requested and abandoned on `StrongBoxUnavailableException`: it is the difference
 * between a key held in the TEE and one held in a separate secure element, and no device is
 * required to have the latter.
 *
 * ## The prompt
 *
 * `BIOMETRIC_STRONG` only — no `DEVICE_CREDENTIAL`. Not a preference: a per-operation
 * biometric-bound key does not accept a device-credential authentication, and the combination with
 * a `CryptoObject` is rejected outright below API 30. Because the credential fallback is absent,
 * `setNegativeButtonText` is mandatory, and it names the real fallback — the password field the
 * user came from.
 *
 * `setConfirmationRequired` is left at its default (true). For passive modalities like face unlock
 * that means one extra tap before a vault opens, which is worth it here.
 */
internal class AndroidBioAuthService(
    private val context: Context,
    private val activityProvider: ActivityProvider,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : BioAuthService {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Asked of a [Context], never of the Activity: this is polled while the login screen is being
     * typed into, including before anything has resumed, and answering "unavailable" then would
     * hide the button on a device that has a perfectly good sensor.
     */
    override suspend fun canAuthenticate(): BiometricAvailability = withContext(coroutinesContextFacade.io) {
        when (BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricAvailability.Available
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricAvailability.NoHardware
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricAvailability.NotEnrolled
            // HW_UNAVAILABLE, SECURITY_UPDATE_REQUIRED, STATUS_UNKNOWN: all temporary or unknowable
            // from here, and all recoverable by the user, so none of them hides the setting.
            else -> BiometricAvailability.Unavailable
        }
    }

    override suspend fun enroll(alias: String, secret: ByteArray): BioAuthService.EnrollOutcome {
        val cipher = withContext(coroutinesContextFacade.io) {
            runCatching {
                Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, generateKey(alias)) }
            }
        }.getOrElse {
            KLogger.e(it) { "biometric enroll: could not prepare a key for the prompt" }
            return BioAuthService.EnrollOutcome.Failed(it.asBioAuthFailure())
        }

        return when (val result = prompt(cipher, ENROLL_TITLE, ENROLL_SUBTITLE)) {
            is PromptResult.Failed -> {
                // The key exists but nothing is sealed under it. The caller clears the alias; this
                // is only the report.
                BioAuthService.EnrollOutcome.Failed(result.reason)
            }
            is PromptResult.Succeeded -> runCatching {
                // Read the IV before doFinal: GCM keys are generated with randomised encryption, so
                // the IV comes from init() and is the only thing that makes the ciphertext openable.
                val iv = result.cipher.iv
                BioAuthService.EnrollOutcome.Enrolled(
                    WrappedSecret(ciphertext = result.cipher.doFinal(secret), iv = iv),
                )
            }.getOrElse {
                KLogger.e(it) { "biometric enroll: sealing the secret failed after a successful prompt" }
                BioAuthService.EnrollOutcome.Failed(it.asBioAuthFailure())
            }
        }
    }

    override suspend fun unlock(alias: String, wrapped: WrappedSecret): BioAuthService.UnlockOutcome {
        val cipher = withContext(coroutinesContextFacade.io) {
            runCatching {
                // A stored blob whose key has vanished is the same situation as an invalidated one,
                // and has the same fix, so it is reported the same way rather than as a generic
                // failure the user would be invited to retry forever.
                val key = keyStore.getKey(alias, null) as? SecretKey ?: throw MissingBiometricKey(alias)
                Cipher.getInstance(TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, wrapped.iv))
                }
            }
        }.getOrElse {
            KLogger.w(it) { "biometric unlock: could not prepare the cipher — ${it::class.simpleName}" }
            return BioAuthService.UnlockOutcome.Failed(it.asBioAuthFailure())
        }

        return when (val result = prompt(cipher, UNLOCK_TITLE, UNLOCK_SUBTITLE)) {
            is PromptResult.Failed -> BioAuthService.UnlockOutcome.Failed(result.reason)
            is PromptResult.Succeeded -> runCatching {
                BioAuthService.UnlockOutcome.Unlocked(result.cipher.doFinal(wrapped.ciphertext))
            }.getOrElse {
                // A GCM tag mismatch here means the stored bytes do not belong to this key. Not
                // "permanently invalidated" — the key is fine — so the caller keeps the enrolment
                // and the user can try again or turn it off.
                KLogger.e(it) { "biometric unlock: the sealed secret did not open" }
                BioAuthService.UnlockOutcome.Failed(it.asBioAuthFailure())
            }
        }
    }

    override suspend fun discard(alias: String) {
        withContext(coroutinesContextFacade.io) {
            runCatching { keyStore.deleteEntry(alias) }
                .onFailure { KLogger.w(it) { "biometric unlock: could not delete the key for this account" } }
        }
    }

    /**
     * Show the system prompt with [cipher] bound to it, and hand back the authorised cipher.
     *
     * The Activity is fetched **per call**. The version this replaced captured
     * `activityProvider.get()` once, in a constructor, from a Koin `single` — so it held whichever
     * Activity happened to be on top when the graph was first touched, kept it alive for the process
     * lifetime, and after the first rotation was pointing at a destroyed one. The prompt then either
     * never appeared or threw.
     */
    private suspend fun prompt(cipher: Cipher, title: String, subtitle: String): PromptResult =
        // Explicit type argument: the early `return@withContext` is a Failed, and without it the
        // block's type infers to that subtype and rejects the Succeeded the callback resumes with.
        withContext<PromptResult>(coroutinesContextFacade.main) {
            val host = activityProvider.get()
            val activity = host as? FragmentActivity
            if (activity == null) {
                // An unchecked `as AppCompatActivity` used to live here. Every Activity in this app
                // is one today, but a crash is not the right answer to a host that is not — the
                // feature is optional and the password field is right there.
                KLogger.w {
                    "biometric prompt: no FragmentActivity to host it (${host?.let { it::class.simpleName } ?: "no foreground activity"})"
                }
                return@withContext PromptResult.Failed(BioAuthFailure.Unavailable)
            }

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText(NEGATIVE_BUTTON)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            suspendCancellableCoroutine { continuation ->
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationFailed() {
                        // NOT terminal. This is one finger that did not match; the prompt stays up
                        // and the user tries again. Resuming here — as the previous implementation
                        // did — resolved the call while the system dialog was still on screen, so a
                        // smudged first touch reported failure and then a *second* result arrived
                        // for a continuation that was already spent.
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authorised = result.cryptoObject?.cipher
                        if (!continuation.isActive) return
                        continuation.resume(
                            // No authorised cipher means the match happened but the key was not
                            // unlocked with it, which is exactly the case this design refuses to
                            // treat as success.
                            authorised?.let(PromptResult::Succeeded)
                                ?: PromptResult.Failed(BioAuthFailure.Failed),
                        )
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (continuation.isActive) continuation.resume(PromptResult.Failed(errorCode.asBioAuthFailure()))
                    }
                }

                val executor = ContextCompat.getMainExecutor(activity)
                val prompt = BiometricPrompt(activity, executor, callback)
                // Cancellation arrives on whatever thread cancelled us; the prompt is a UI object.
                continuation.invokeOnCancellation { executor.execute { prompt.cancelAuthentication() } }
                prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            }
        }

    /**
     * A fresh key for [alias], replacing whatever was there.
     *
     * The delete is not tidiness: re-enrolling has to invalidate every blob made under the old key,
     * and the only way to guarantee that is for the old key to stop existing.
     */
    private fun generateKey(alias: String): SecretKey {
        runCatching { keyStore.deleteEntry(alias) }
            .onFailure { KLogger.w(it) { "biometric enroll: could not remove the previous key before regenerating" } }
        return runCatching { generateKey(alias, strongBox = true) }.getOrElse { failure ->
            if (failure !is StrongBoxUnavailableException) throw failure
            KLogger.d { "biometric enroll: no StrongBox on this device — falling back to the TEE" }
            generateKey(alias, strongBox = false)
        }
    }

    private fun generateKey(alias: String, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE_BITS)
            .setUserAuthenticationRequired(true)
            // 0 = per operation. Anything larger turns this into a time window and gives up the
            // property that the cipher must travel through the prompt.
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    private sealed interface PromptResult {
        /** The cipher the *system* authorised, not the one that was handed to it. */
        data class Succeeded(val cipher: Cipher) : PromptResult
        data class Failed(val reason: BioAuthFailure) : PromptResult
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_SIZE_BITS = 256
        const val GCM_TAG_BITS = 128

        const val ENROLL_TITLE = "Turn on biometric unlock"
        const val ENROLL_SUBTITLE = "Passman will unlock your vault with this biometric"
        const val UNLOCK_TITLE = "Unlock Passman"
        const val UNLOCK_SUBTITLE = "Use your biometric to open your vault"

        /** Names the real fallback. There is no device-credential option to offer instead. */
        const val NEGATIVE_BUTTON = "Use password"
    }
}

/** The stored blob outlived its key. Same user-visible situation as an invalidated key. */
private class MissingBiometricKey(alias: String) : IllegalStateException("no biometric key for $alias")

/**
 * The keystore conditions that mean "this enrolment is over" versus everything else.
 *
 * [KeyPermanentlyInvalidatedException] is the designed one: biometrics changed.
 * [UserNotAuthenticatedException] should be unreachable — a per-operation key authenticates through
 * the `CryptoObject`, never on a timer — but if it ever fires, the recovery is identical (re-enrol
 * with the password), so it is reported identically rather than as a mystery.
 * [UnrecoverableKeyException] is what some OEM keystores raise instead of the first one.
 *
 * The cause chain is walked because the keystore provider wraps freely.
 */
private fun Throwable.asBioAuthFailure(): BioAuthFailure {
    var cursor: Throwable? = this
    while (cursor != null) {
        when (cursor) {
            is KeyPermanentlyInvalidatedException,
            is UserNotAuthenticatedException,
            is UnrecoverableKeyException,
            is MissingBiometricKey,
            -> return BioAuthFailure.PermanentlyInvalidated
            else -> Unit
        }
        cursor = cursor.cause?.takeIf { it !== cursor }
    }
    return BioAuthFailure.Failed
}

private fun Int.asBioAuthFailure(): BioAuthFailure = when (this) {
    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
    BiometricPrompt.ERROR_USER_CANCELED,
    BiometricPrompt.ERROR_CANCELED,
    -> BioAuthFailure.Cancelled

    BiometricPrompt.ERROR_LOCKOUT,
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
    -> BioAuthFailure.Lockout

    BiometricPrompt.ERROR_HW_NOT_PRESENT,
    BiometricPrompt.ERROR_HW_UNAVAILABLE,
    BiometricPrompt.ERROR_NO_BIOMETRICS,
    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
    BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED,
    -> BioAuthFailure.Unavailable

    // TIMEOUT, UNABLE_TO_PROCESS, NO_SPACE, VENDOR: retryable, and the user is looking at the
    // prompt when they happen.
    else -> BioAuthFailure.Failed
}
