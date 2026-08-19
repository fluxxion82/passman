package ai.passman.viewmodel.keystore.create

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.keystore.AddKeystoreKey
import ai.passman.domain.keystore.GetKeystore
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.password.AddPassword
import ai.passman.viewvo.navigation.AddKeyStorKeyNavigation
import ai.passman.viewvo.navigation.ErrorCreation
import ai.passman.viewvo.navigation.SuccessCreation
import ai.passman.viewmodel.passphrase.PasswordViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class AddKeystoreKeyViewModel(
    val keystorePath: String,
    val keystoreName: String,
    private val getKeystore: GetKeystore,
    private val addKeystoreKey: AddKeystoreKey,
    private val addPassword: AddPassword,
): PasswordViewModel() {
    val navigation = Channel<AddKeyStorKeyNavigation>(Channel.RENDEZVOUS)

    private val keyStorePath = MutableStateFlow("")
    val keyStoreName = MutableStateFlow("")

    val keyStoreType = MutableStateFlow(KeyStoreType.PKCS12)
    val keyAlias = MutableStateFlow("")
    val keyAlgorithm = MutableStateFlow(KeystoreKeyAlgorithm.RSA)
    val keyPassword = MutableStateFlow("")
    val keystorePassword = MutableStateFlow("")

    val isSavePassToListChecked = MutableStateFlow(false)

    /** Adding a key runs a slow keygen; a double-tap would mint two keys. */
    val isLoading = MutableStateFlow(false)

    init {
        KLogger.d {
            "keystore path: $keystorePath"
        }
        viewModelScope.launch {
            keyStorePath.emit(keystorePath)

            getKeystore(GetKeystore.GetKeystoreRequest(keystorePath, keystoreName)).collect {
                KLogger.d {
                    "init keystore found: ${it.name}"
                }

                keyStoreType.emit(it.type)
                keyStoreName.emit(it.name)
            }
        }
    }

    fun onKeyAliasChanged(alias: String) {
        viewModelScope.launch {
            keyAlias.emit(alias)
        }
    }

    fun onKeyPasswordChanged(keyPass: String) {
        viewModelScope.launch {
            keyPassword.emit(keyPass)
        }
    }

    fun onSavePasswordClicked(isChecked: Boolean) {
        viewModelScope.launch {
            isSavePassToListChecked.emit(isChecked)
        }
    }

    fun onKeyAlgorithmPicked(keyAlgorithm: KeystoreKeyAlgorithm) {
        KLogger.d {
            "onKeyAlgorithmPicked: ${keyAlgorithm.name}"
        }
        viewModelScope.launch {
            this@AddKeystoreKeyViewModel.keyAlgorithm.emit(keyAlgorithm)
        }
    }

    fun onKeystorePasswordChanged(keyStorePassword: String) {
        viewModelScope.launch { keystorePassword.emit(keyStorePassword) }
    }

    fun onAddKeyClick() {
        if (isLoading.value) return
        isLoading.value = true
        viewModelScope.launch {
            val outcome = addKeystoreKey(
                AddKeystoreKey.UpdateKeystoreRequest(
                    keystorePath = keystorePath,
                    keystoreName = keyStoreName.value,
                    keystorePassword = keystorePassword.value,
                    newKeyAlias = keyAlias.value,
                    newKeyPassword = keyPassword.value,
                    newKeyAlgo = keyAlgorithm.value,
                )
            )

            if (outcome.isSuccessful()) {
                if (isSavePassToListChecked.value) {
                    addPassword(
                        AddPassword.EntryData(
                            entryName = "${keyStoreName.value}: ${keyAlias.value}",
                            userName = keyAlias.value,
                            password = keyPassword.value,
                            website = "",
                            notes = "",
                        )
                    )
                }

                navigation.send(SuccessCreation)
            } else {
                isLoading.value = false
                navigation.send(ErrorCreation(message = outcome.message))
            }
        }
    }
}
