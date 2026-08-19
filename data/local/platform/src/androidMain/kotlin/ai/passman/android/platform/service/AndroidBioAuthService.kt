package ai.passman.android.platform.service

import ai.passman.platform.service.BioAuthService
import ai.passman.domain.base.CoroutinesContextFacade
import android.app.Activity
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal class AndroidBioAuthService(
    activityProvider: ActivityProvider,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : BioAuthService {
    private var activity: Activity? = activityProvider.get()

    override suspend fun authenticate(hardwareKeySeed: ByteArray?): BioAuthService.Result =
        withContext<BioAuthService.Result>(coroutinesContextFacade.main) {
            val act = activity ?: return@withContext BioAuthService.Result.Unavailable
            suspendCancellableCoroutine { cont ->
                val cryptoObject = hardwareKeySeed?.let { seed ->
                    runCatching {
                        val publicKey = KeyFactory.getInstance("RSA")
                            .generatePublic(X509EncodedKeySpec(seed))
                        Cipher.getInstance("RSA").apply { init(Cipher.ENCRYPT_MODE, publicKey) }
                    }.getOrNull()?.let(BiometricPrompt::CryptoObject)
                }

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Biometric Authentication")
                    .setSubtitle("Authenticate using a biometric sensor")
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG
                            or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()

                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationFailed() {
                        if (cont.isActive) cont.resume(BioAuthService.Result.Failed)
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (cont.isActive) cont.resume(BioAuthService.Result.Success)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) cont.resume(BioAuthService.Result.Failed)
                    }
                }

                val prompt = BiometricPrompt(
                    act as AppCompatActivity,
                    ContextCompat.getMainExecutor(act),
                    callback,
                )

                if (cryptoObject != null) {
                    prompt.authenticate(promptInfo, cryptoObject)
                } else {
                    prompt.authenticate(promptInfo)
                }
            }
        }
}
