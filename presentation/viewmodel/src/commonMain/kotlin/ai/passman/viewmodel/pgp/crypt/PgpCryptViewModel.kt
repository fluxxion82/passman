package ai.passman.viewmodel.pgp.crypt

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.pgp.*
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.viewmodel.base.BaseViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class PgpCryptViewModel(
    private val keyId: Long,
    initialAction: CryptAction,
    initialFileTarget: Boolean,
    private val getPgpKey: GetPgpKey,
    private val encryptPgp: EncryptPgp,
    private val encryptAndSignPgp: EncryptAndSignPgp,
    private val decryptPgp: DecryptPgp,
    private val clearSign: ClearSignPgp,
    private val decryptAndVerifyPgp: DecryptAndVerify,
    private val verifyClearSignature: VerifyClearSignature,
    private val copyToClipboard: CopyToClipboard,
) : BaseViewModel() {
    val action = MutableStateFlow(initialAction)
    val isFileTarget = MutableStateFlow(initialFileTarget)
    val availableActions = MutableStateFlow<List<CryptAction>>(emptyList())
    val selectedFilePath = MutableStateFlow("")
    val keyPassword = MutableStateFlow("")
    val currentUserId = MutableStateFlow("")

    val subKeys = MutableStateFlow(listOf<String>())
    val inputText = MutableStateFlow("")
    val outputText = MutableStateFlow("")

    val optionSelected = MutableStateFlow(-1)

    val pgpKey = MutableStateFlow<PgpKeyPair?>(null)
    val isLoading = MutableStateFlow(false)
    val isError = MutableStateFlow(false)
    val errorMessage = MutableStateFlow<String?>(null)

    init {
        KLogger.d {
            """
                key id: $keyId
                action: ${action.value}
                isFile: ${isFileTarget.value}
            """.trimIndent()
        }
        viewModelScope.launch {
            val key = getPgpKey(keyId) ?: return@launch
            pgpKey.emit(key)
            availableActions.emit(
                if (key.secretKey == null) {
                    listOf(CryptAction.ENCRYPT, CryptAction.VERIFY)
                } else {
                    CryptAction.entries.toList()
                }
            )
            // subKeys.emit(key)
            currentUserId.emit(
                key.publicKey.userIds.first().copy(comment = "").toString()
            )
        }
    }

    private suspend fun doEncrypt() {
        val request = if (isFileTarget.value) {
            EncryptPgp.EncryptPgpData.EncryptPgpFile(selectedFilePath.value, pgpKey.value!!.publicKey.path)
        } else {
            EncryptPgp.EncryptPgpData.EncryptPgpText(inputText.value, pgpKey.value!!.publicKey.path)
        }
        when (val encrypted = encryptPgp(request)) {
            is Outcome.Success -> {
                KLogger.i { "encrypted: ${encrypted.value}" }
                outputText.value = encrypted.value
            }
            is Outcome.Error -> {
                KLogger.i { "error encrypting:${encrypted.message}" }
                reportError(encrypted.message, "Encryption failed.")
            }
        }
    }

    private suspend fun doDecrypt() {
        val request = if (isFileTarget.value) {
            DecryptPgp.DecryptPgpData.DecryptPgpFile(selectedFilePath.value, pgpKey.value!!.secretKey!!.path, keyPassword.value)
        } else {
            DecryptPgp.DecryptPgpData.DecryptPgpText(inputText.value, pgpKey.value!!.secretKey!!.path, keyPassword.value)
        }

        when (val decrypted = decryptPgp(request)) {
            is Outcome.Success -> {
                KLogger.i { "decrypted: ${decrypted.value}" }
                outputText.emit(decrypted.value)
            }
            is Outcome.Error -> {
                KLogger.i {
                    "error decrypting: ${decrypted.message}"
                }
                reportError(decrypted.message, "Decryption failed.")
            }
        }
    }

    private suspend fun doClearSign() {
        val request = if (isFileTarget.value) {
            ClearSignPgp.ClearSignPgpFile(selectedFilePath.value, pgpKey.value!!.secretKey!!.path, keyPassword.value)
        } else {
            ClearSignPgp.ClearSignPgpText(inputText.value, pgpKey.value!!.secretKey!!.path, keyPassword.value)
        }
        when (val signed = clearSign(request)) {
            is Outcome.Success -> {
                KLogger.i { "decrypted: ${signed.value}" }
                outputText.emit(signed.value)
            }
            is Outcome.Error -> {
                KLogger.i {
                    "error decrypting: ${signed.message}"
                }
                reportError(signed.message, "Signing failed.")
            }
        }
    }

    private suspend fun verifySign() {
        val request = if (isFileTarget.value) {
            VerifyClearSignature.VerifyClearSignPgpFile(selectedFilePath.value, pgpKey.value!!.publicKey.path)
        } else {
            VerifyClearSignature.VerifyClearSignPgpText(inputText.value, pgpKey.value!!.publicKey.path)
        }
        when (val outcome = verifyClearSignature(request)) {
            is Outcome.Error -> {
                reportError(outcome.message, "Signature verification failed.")
            }
            is Outcome.Success -> outputText.emit("Signature is valid.")
        }
    }

    private suspend fun decryptAndVerify() {
        val request = if (isFileTarget.value) {
            DecryptAndVerify.DecryptAndVerifyFile(selectedFilePath.value, pgpKey.value!!.secretKey!!.path, pgpKey.value!!.publicKey.path, keyPassword.value)
        } else {
            DecryptAndVerify.DecryptAndVerifyText(inputText.value, pgpKey.value!!.secretKey!!.path, pgpKey.value!!.publicKey.path, keyPassword.value)
        }
        when (val outcome = decryptAndVerifyPgp(request)) {
            is Outcome.Error -> {
                reportError(outcome.message, "Decryption and signature verification failed.")
            }
            is Outcome.Success -> outputText.emit(outcome.value)
        }
    }

    private suspend fun encryptAndSign() {
        val request = if (isFileTarget.value) {
            EncryptAndSignPgp.EncryptAndSignPgpFile(selectedFilePath.value, pgpKey.value!!.publicKey.path, pgpKey.value!!.secretKey!!.path, keyPassword.value, true)
        } else {
            EncryptAndSignPgp.EncryptAndSignPgpText(inputText.value, pgpKey.value!!.publicKey.path, pgpKey.value!!.secretKey!!.path, keyPassword.value, true)
        }
        when (val outcome = encryptAndSignPgp(request)) {
            is Outcome.Error -> {
                reportError(outcome.message, "Encryption and signing failed.")
            }
            is Outcome.Success -> outputText.emit(outcome.value)
        }
    }

    fun onFileSelectedChanged(file: String) {
        viewModelScope.launch {
            selectedFilePath.emit(file)
        }
    }

    fun onUserIdSelected(userId: String) {
        viewModelScope.launch {
            currentUserId.emit(userId)
        }
    }

    fun onPasswordChanged(password: String) {
        viewModelScope.launch {
            isError.emit(false)
            errorMessage.emit(null)
            keyPassword.emit(password)
        }
    }

    fun onInputTextChanged(inputText: String) {
        viewModelScope.launch {
            isError.emit(false)
            errorMessage.emit(null)
            this@PgpCryptViewModel.inputText.emit(inputText)
            outputText.emit("")
        }
    }

    fun onActionSelected(selectedAction: CryptAction) {
        viewModelScope.launch {
            action.emit(selectedAction)
            clearOutputAndError()
        }
    }

    fun onTargetToggle(file: Boolean) {
        viewModelScope.launch {
            isFileTarget.emit(file)
            clearOutputAndError()
        }
    }

    fun onActionClick() {
        viewModelScope.launch {
            isLoading.emit(true)
            isError.emit(false)
            errorMessage.emit(null)

            when (action.value) {
                CryptAction.ENCRYPT -> doEncrypt()
                CryptAction.DECRYPT -> doDecrypt()
                CryptAction.SIGN -> doClearSign()
                CryptAction.VERIFY -> verifySign()
                CryptAction.ENCRYPT_AND_SIGN -> encryptAndSign()
                CryptAction.DECRYPT_AND_VERIFY -> decryptAndVerify()
            }

            isLoading.emit(false)
        }
    }

    fun onCopyClicked(inputText: String) {
        viewModelScope.launch {
            copyToClipboard(inputText)
        }
    }

    private suspend fun clearOutputAndError() {
        inputText.emit("")
        outputText.emit("")
        isError.emit(false)
        errorMessage.emit(null)
    }

    private suspend fun reportError(message: String, fallback: String) {
        isError.emit(true)
        errorMessage.emit(message.ifBlank { fallback })
    }

    /**
     * Drop the key password when the screen goes away.
     *
     * The saved-password picker keeps nothing after a session — its result is a replay-free event —
     * so [keyPassword] is the one copy of a vault secret that outlives the tap, and it lives exactly
     * as long as this view model does. Clearing it here bounds that to the screen, whether the
     * password arrived from the picker or from the keyboard.
     *
     * Assigned rather than emitted: the scope is already cancelled by the time this runs.
     */
    override fun onCleared() {
        keyPassword.value = ""
        super.onCleared()
    }
}
