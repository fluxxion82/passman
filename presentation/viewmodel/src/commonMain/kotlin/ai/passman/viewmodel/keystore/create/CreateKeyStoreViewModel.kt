package ai.passman.viewmodel.keystore.create

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.CreateKeyStore
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.password.AddPassword
import ai.passman.viewvo.navigation.CreateKeyStoreNavigation
import ai.passman.viewvo.navigation.ErrorCreation
import ai.passman.viewvo.navigation.SuccessCreation
import ai.passman.viewmodel.passphrase.PasswordViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

open class CreateKeyStoreViewModel(
    val createKeyStore: CreateKeyStore,
    private val addPassword: AddPassword,
) : PasswordViewModel() {
    val navigation = Channel<CreateKeyStoreNavigation>(Channel.RENDEZVOUS)

    val keyStoreName = MutableStateFlow("") // androidKeyStore.jks  myKeyStore.pfx
    val keystorePassword = MutableStateFlow("")
    val keyAlgorithm = MutableStateFlow(KeystoreKeyAlgorithm.RSA)
    val keyAlias = MutableStateFlow("")
    val aliasPassword = MutableStateFlow("")

    val isSaveStorePassToListChecked = MutableStateFlow(false)
    val isSaveKeyPassToListChecked = MutableStateFlow(false)

    /** Keystore creation runs a slow keygen; a double-tap would mint two stores. */
    val isLoading = MutableStateFlow(false)

    fun onCreate() {
        if (isLoading.value) return
        isLoading.value = true
        viewModelScope.launch {
            when (
                val outcome = createKeyStore(
                    CreateKeyStore.CreateRequest(
                        keystoreName = keyStoreName.value,
                        keystorePassword = keystorePassword.value,
                        keyAlgorithm = keyAlgorithm.value,
                        keyAlias = keyAlias.value,
                        aliasPassword = aliasPassword.value,
                        keystoreType = KeyStoreType.PKCS12,
                    )
                )
            ) {
                is Outcome.Error -> {
                    isLoading.value = false
                    navigation.send(ErrorCreation(outcome.message))
                }
                is Outcome.Success -> {
                    if (isSaveStorePassToListChecked.value) {
                        addPassword(
                            AddPassword.EntryData(
                                entryName = keyStoreName.value,
                                userName = keyStoreName.value,
                                password = keystorePassword.value,
                                website = "",
                                notes = "",
                            )
                        )
                    }

                    if (isSaveKeyPassToListChecked.value) {
                        addPassword(
                            AddPassword.EntryData(
                                entryName = "${keyStoreName.value}: ${keyAlias.value}",
                                userName = keyAlias.value,
                                password = aliasPassword.value,
                                website = "",
                                notes = "",
                            )
                        )
                    }
                    navigation.send(SuccessCreation)
                }
            }
        }
    }

    fun onKeyAlgorithmPicked(keyAlgo: KeystoreKeyAlgorithm) {
        KLogger.d {
            "onKeyAlgorithmPicked: ${keyAlgo.name}"
        }
        viewModelScope.launch {
            keyAlgorithm.emit(keyAlgo)
        }
    }

    fun onKeystoreNameChanged(name: String) {
        viewModelScope.launch { keyStoreName.emit(name) }
    }

    fun onKeystorePasswordChanged(password: String) {
        viewModelScope.launch { keystorePassword.emit(password) }
    }

    fun onKeyAliasChanged(alias: String) {
        viewModelScope.launch { keyAlias.emit(alias) }
    }

    fun onKeyPasswordChanged(keyPass: String) {
        viewModelScope.launch { aliasPassword.emit(keyPass) }
    }

    fun onSaveStorePasswordClicked(isChecked: Boolean) {
        viewModelScope.launch {
            isSaveStorePassToListChecked.emit(isChecked)
        }
    }

    fun onSaveKeyPasswordClicked(isChecked: Boolean) {
        viewModelScope.launch {
            isSaveKeyPassToListChecked.emit(isChecked)
        }
    }

    fun onReGenStorePass() {
        viewModelScope.launch {
            onReGenPass()
            val pass = password.first { it.isNotEmpty() && it != aliasPassword.value }
            keystorePassword.emit(pass)
        }
    }

    fun onReGenKeyPass() {
        viewModelScope.launch {
            onReGenPass()
            val pass = password.first { it.isNotEmpty() && it != keystorePassword.value}
            aliasPassword.emit(pass)
        }
    }
}
