package ai.passman.viewmodel.keystore.crypt

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.keystore.*
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.viewmodel.base.BaseViewModel
import androidx.lifecycle.viewModelScope
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

@OptIn(ExperimentalEncodingApi::class)
open class KeystoreCryptViewModel(
    val keystorePath: String,
    val keystoreName: String,
    val keyAlias: String,
    initialAction: CryptAction,
    initialFileTarget: Boolean,
    private val getKeystoreKey: GetKeystoreKey,
    private val encrypt: Encrypt,
    private val decrypt: Decrypt,
    private val sign: SignWithKey,
    private val verifySignatureKeystore: VerifySignatureKeystore,
    private val copyToClipboard: CopyToClipboard,
) : BaseViewModel() {
    val action = MutableStateFlow(initialAction)
    val isFileTarget = MutableStateFlow(initialFileTarget)
    val availableActions = MutableStateFlow(CryptAction.entries.toList())
    val keystoreKeyAlgorithm = MutableStateFlow(KeystoreKeyAlgorithm.RSA)
    val aliasPassword = MutableStateFlow("")
    val selectedFilePath = MutableStateFlow("")

    val inputText = MutableStateFlow("")
    val inputSignatureData = MutableStateFlow("")
    val outputData = MutableStateFlow("")

    val useSalt = MutableStateFlow(false)
    val saltIv = MutableStateFlow("")
    val isLoading = MutableStateFlow(false)
    val isError = MutableStateFlow(false)
    val errorMessage = MutableStateFlow<String?>(null)

    init {
        KLogger.d {
            "keyAlias: $keyAlias from $keystoreName"
        }
        viewModelScope.launch {
            val keystoreKey = getKeystoreKey(
                GetKeystoreKey.KeystoreKeyRequest(
                    keystorePath = keystorePath,
                    keystoreName = keystoreName,
                    keyAlias = keyAlias,
                )
            )

            keystoreKeyAlgorithm.emit(keystoreKey.keyAlgorithm)
        }
    }

    fun onFileSelectedChanged(file: String) {
        viewModelScope.launch {
            selectedFilePath.emit(file)
        }
    }

    fun onPasswordChanged(password: String) {
        viewModelScope.launch {
            isError.emit(false)
            errorMessage.emit(null)
            this@KeystoreCryptViewModel.aliasPassword.emit(password)
        }
    }

    fun onInputTextChanged(inputText: String) {
        viewModelScope.launch {
            isError.emit(false)
            errorMessage.emit(null)
            this@KeystoreCryptViewModel.inputText.emit(inputText)
            outputData.emit("")
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

    fun onInputSignatureChanged(inputSignature: String) {
        viewModelScope.launch {
            inputSignatureData.emit(inputSignature)
        }
    }

    fun regenSalt() {
        viewModelScope.launch {
            val salt = Random.nextBytes(KEY_LENGTH)
            saltIv.emit(Base64.encode(salt))
        }
    }

    fun onSaltIvChecked(checked: Boolean) {
        viewModelScope.launch {
            useSalt.emit(checked)
        }
    }

    fun onSaltIvChanged(salt: String) {
        viewModelScope.launch {
            saltIv.emit(salt)
        }
    }

    fun onActionClick() {
        viewModelScope.launch {
            KLogger.d {
                "action click: ${action.value}"
            }
            isLoading.emit(true)
            isError.emit(false)
            errorMessage.emit(null)

            when (action.value) {
                CryptAction.ENCRYPT -> doEncrypt()
                CryptAction.DECRYPT -> doDecrypt()
                CryptAction.SIGN -> doClearSign()
                CryptAction.VERIFY -> doVerify()
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

    /**
     * Drop the alias password when the screen goes away.
     *
     * The saved-password picker keeps nothing after a session — its result is a replay-free event —
     * so [aliasPassword] is the one copy of a vault secret that outlives the tap, and it lives
     * exactly as long as this view model does. Clearing it here bounds that to the screen, whether
     * the password arrived from the picker or from the keyboard.
     *
     * Assigned rather than emitted: the scope is already cancelled by the time this runs.
     */
    override fun onCleared() {
        aliasPassword.value = ""
        super.onCleared()
    }

    private suspend fun encryptData(inputData: String): String? {
        val request = if (isFileTarget.value) {
            Encrypt.EncryptKeystoreData.EncryptFile(
                keystorePath = keystorePath, keystoreName = keystoreName, keyAlias = keyAlias, keyPassword = aliasPassword.value, filePath = inputData, salt = saltIv.value,
            )
        } else {
            Encrypt.EncryptKeystoreData.EncryptText(
                keystorePath = keystorePath, keystoreName = keystoreName, keyAlias = keyAlias, keyPassword = aliasPassword.value, plaintext = inputData, salt = saltIv.value,
            )
        }
        return when (val encryptOutcome = encrypt(request)) {
            is Outcome.Success -> {
                val encryptedData = encryptOutcome.value
                val cipherText = encryptedData.ciphertextOrPath
                // saltIv.value = Base64.encode(encryptedData.cipherIv?.encodeToByteArray() ?: saltIv.value.encodeToByteArray())
                cipherText
            }
            is Outcome.Error -> {
                KLogger.i { "error encrypting:${encryptOutcome.message}" }
                reportError(encryptOutcome.message, "Encryption failed.")
                null
            }
        }
    }

    private suspend fun decryptData(inputData: String): String? {
        val request = if (isFileTarget.value) {
            Decrypt.DecryptKeystoreData.DecryptFile(
                keystorePath = keystorePath,
                keystoreName = keystoreName,
                keyAlias = keyAlias,
                keyPassword = aliasPassword.value,
                cipherSalt = saltIv.value,
                encryptedFilePath = inputData,
            )
        } else {
            Decrypt.DecryptKeystoreData.DecryptText(
                keystorePath = keystorePath,
                keystoreName = keystoreName,
                keyAlias = keyAlias,
                keyPassword = aliasPassword.value,
                cipherSalt = saltIv.value,
                cipherText = inputData,
            )
        }

        return when (val decrypted = decrypt(request)) {
            is Outcome.Success -> {
                KLogger.i { "decrypted: ${decrypted.value}" }
                decrypted.value
            }
            is Outcome.Error -> {
                KLogger.i {
                    "error decrypting: ${decrypted.message}"
                }
                reportError(decrypted.message, "Decryption failed.")
                null
            }
        }
    }

    private suspend fun signData(dataToSign: String): String? {
        val request = if (isFileTarget.value) {
            SignWithKey.SignFile(
                filePath = dataToSign,
                keystorePath = keystorePath,
                keystoreName = keystoreName,
                keyAlias = keyAlias,
                keyPassword = aliasPassword.value,
            )
        } else {
            SignWithKey.SignText(
                keystorePath = keystorePath,
                keystoreName = keystoreName,
                keyAlias = keyAlias,
                dataToSign = dataToSign,
                keyPassword = aliasPassword.value,
            )
        }

        return when (val signed = sign(request)) {
            is Outcome.Success -> {
                KLogger.i { "signed: ${signed.value}" }
                // outputData.emit(signed.value)

                signed.value
            }
            is Outcome.Error -> {
                KLogger.i {
                    "error signing: ${signed.message}"
                }
                reportError(signed.message, "Signing failed.")
                null
            }
        }
    }

    private suspend fun verifyData(inputData: String, inputSignature: String): Boolean? {
        val request = if (isFileTarget.value) {
            VerifySignatureKeystore.VerifySignFile(
                selectedFilePath.value,
                keystorePath = keystorePath,
                keystoreName = keystoreName,
                signature = inputSignature,
                keyAlias = keyAlias,
            )
        } else {
            VerifySignatureKeystore.VerifySignText(
                signature =  inputSignature,
                keystorePath = keystorePath,
                keystoreName = keystoreName,
                data = inputText.value,
                keyAlias = keyAlias,
            )
        }
        return when (val outcome = verifySignatureKeystore(request)) {
            is Outcome.Error -> {
                reportError(outcome.message, "Signature verification failed.")
                null
            }
            is Outcome.Success -> outcome.value
        }
    }

    private suspend fun doEncrypt() {
        val encryptedText = encryptData(if (isFileTarget.value) selectedFilePath.value else inputText.value)
        if (encryptedText != null) {
            outputData.emit(encryptedText)
        }
    }

    private suspend fun doDecrypt() {
        val decryptedText = decryptData(if (isFileTarget.value) selectedFilePath.value else inputText.value)
        if (decryptedText != null) {
            outputData.emit(decryptedText)
        }
    }

    private suspend fun doClearSign() {
        val signed = signData(if (isFileTarget.value) selectedFilePath.value else inputText.value)
        if (signed != null) {
            outputData.emit(signed)
        }
    }

    private suspend fun doVerify() {
        val verified = verifyData(inputText.value, inputSignatureData.value)
        if (verified != null) {
            outputData.emit(if (verified) "Signature is valid." else "Signature is not valid.")
        }
    }

    private suspend fun encryptAndSign() {
        val input = if (isFileTarget.value) {
            selectedFilePath.value
        } else {
            inputText.value
        }
        val encryptedText = encryptData(input)
        if (encryptedText != null) {
            val signature = signData(encryptedText)
            if (signature != null) {
                val output = """
                    encrypted:
                    $encryptedText

                    signed:
                    $signature
                """.trimIndent()

                outputData.emit(output)
            }
        }
    }

    private suspend fun decryptAndVerify() {
        val decryptData = if (isFileTarget.value) {
            selectedFilePath.value
        } else {
            inputText.value
        }

        val decryptedData = decryptData(decryptData)
        if (decryptedData != null) {
            val isVerified = verifyData(decryptedData, inputSignatureData.value)
            if (isVerified != null) {
                val output = """
                    decrypted:
                    $decryptedData

                    verified:
                    $isVerified
                """.trimIndent()

                outputData.emit(output)
            }
        }
    }

    private suspend fun clearOutputAndError() {
        inputText.emit("")
        inputSignatureData.emit("")
        outputData.emit("")
        isError.emit(false)
        errorMessage.emit(null)
    }

    private suspend fun reportError(message: String, fallback: String) {
        isError.emit(true)
        errorMessage.emit(message.ifBlank { fallback })
    }

    companion object {
        private const val KEY_LENGTH = 2048 // 1024 //256
    }
}
