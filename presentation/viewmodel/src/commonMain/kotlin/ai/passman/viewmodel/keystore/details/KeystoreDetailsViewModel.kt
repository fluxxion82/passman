package ai.passman.viewmodel.keystore.details

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.keystore.DeleteKeystore
import ai.passman.domain.keystore.DeleteKeystoreKey
import ai.passman.domain.keystore.GetKeystore
import ai.passman.domain.keystore.GetKeystoreAliases
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.model.ShareFileKind
import ai.passman.domain.settings.model.ShareFileRequest
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.*
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class KeystoreDetailsViewModel(
    val keystorePath: String,
    val keystoreName: String,
    private val getKeystore: GetKeystore,
    private val getKeystoreAliases: GetKeystoreAliases,
    private val deleteKeystore: DeleteKeystore,
    private val deleteKeystoreKey: DeleteKeystoreKey,
    private val shareFile: ShareFile,
) : BaseViewModel() {
    val navigation = Channel<KeystoreDetailsNavigation>(Channel.RENDEZVOUS)

    val keystoreInfo = MutableStateFlow<KeyStoreInfo?>(null)
    val keyStoreName = MutableStateFlow("")
    val keyStorePassword = MutableStateFlow("")
    val keyStorePath = MutableStateFlow("")
    val keyAliasList = MutableStateFlow(listOf<KeystoreKey>())

    val isError = MutableStateFlow(false)

    /** Share waiting on the user's confirmation dialog; null when none is pending. */
    val pendingShare = MutableStateFlow<ShareFileRequest?>(null)

    /** One-shot user-facing notices (share failures); collected into the screen's snackbar. */
    val userMessages = Channel<String>(Channel.BUFFERED)

    init {
        KLogger.d {
            "keystore path: $keystorePath"
        }

        viewModelScope.launch {
            keyStoreName.emit(keystoreName)
            keyStorePath.emit(keystorePath)
        }
    }

    fun onDeleteKeystoreClicked() {
        KLogger.d {
            "onDeleteKeystoreClicked"
        }
        viewModelScope.launch {
            val success = deleteKeystore(
                DeleteKeystore.DeleteKeystoreRequest(
                    keystorePath = keystorePath,
                    keystoreName = keyStoreName.value,
                    keystorePassword = keyStorePassword.value,
                )
            )

            if (success) {
                navigation.send(Back)
            } else {
                navigation.send(UpdateKeystoreError)
            }
        }
    }

    fun onPasswordChanged(password: String) {
        viewModelScope.launch {
            keyStorePassword.emit(password)
        }
    }

    fun onDismissPassword() {
        viewModelScope.launch {
            if (keystoreInfo.value == null) {
                isError.emit(true)
            }
        }
    }

    fun onPasswordEntered() {
        viewModelScope.launch {
            getKeystore(GetKeystore.GetKeystoreRequest(keystorePath, keystoreName)).collect {
                KLogger.d { "init keystore found: ${it.name}" }
                keystoreInfo.emit(it)

                if (it.name.isEmpty()) {
                    isError.emit(true)
                    return@collect
                }

                val aliasesOutcome = getKeystoreAliases(
                    GetKeystoreAliases.AliasListRequest(
                        path = keystorePath,
                        name = keyStoreName.value,
                        password = keyStorePassword.value,
                    )
                )

                if (aliasesOutcome.isSuccessful()) {
                    if (aliasesOutcome.value.isNotEmpty()) {
                        keyAliasList.emit(aliasesOutcome.value)
                    }
                } else {
                    isError.emit(true)
                }
            }
        }
    }

    fun onDeleteKeyClick(key: KeystoreKey) {
        KLogger.d { "onDeleteKeyClicked" }
        viewModelScope.launch {
            val success = deleteKeystoreKey(
                DeleteKeystoreKey.DeleteKeystoreKeyRequest(
                    keystorePath = keystorePath,
                    keystoreName = keyStoreName.value,
                    keystorePassword = keyStorePassword.value,
                    keystoreKeyAlias = key.keyAlias,
                )
            )

            if (success) {
                val aliasesOutcome = getKeystoreAliases(
                    GetKeystoreAliases.AliasListRequest(
                        path = keystorePath,
                        name = keyStoreName.value,
                        password = keyStorePassword.value
                    )
                )

                if (aliasesOutcome.isSuccessful()) {
                    keyAliasList.emit(aliasesOutcome.value)
                }
            } else {
                navigation.send(UpdateKeystoreError)
            }
        }
    }

    fun onAddKeyClick() {
        viewModelScope.launch {
            navigation.send(AddKeystoreKey(keystorePath = keyStorePath.value, keystoreName = keystoreName))
        }
    }

    fun onShareKeystoreClick() {
        // keystorePath is the parent directory (getAllKeystores strips the file name); the
        // keystore file itself is directory + name, like every other keystore op. The
        // constructor values, not the flows: those fill asynchronously in init and a click
        // could beat the emit.
        pendingShare.value = ShareFileRequest(
            filePath = "$keystorePath/$keystoreName",
            displayName = keystoreName,
            kind = ShareFileKind.EntireKeystore,
        )
    }

    fun onShareConfirmed() {
        val request = pendingShare.value ?: return
        pendingShare.value = null
        viewModelScope.launch {
            if (!shareFile(request)) {
                userMessages.send("Can't share ${request.displayName}: the keystore file could not be offered")
            }
        }
    }

    fun onShareDismissed() {
        pendingShare.value = null
    }

    fun onKeyToolsClick(key: KeystoreKey) {
        viewModelScope.launch {
            navigation.send(KeystoreTools(keystorePath = keyStorePath.value, keystoreName = keystoreName, keyAlias = key.keyAlias))
        }
    }
}
