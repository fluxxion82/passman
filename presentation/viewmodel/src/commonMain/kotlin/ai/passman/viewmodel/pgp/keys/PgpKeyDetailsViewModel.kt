package ai.passman.viewmodel.pgp.keys

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.ExportPgpPrivateKey
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.GetPgpPublicKeyPath
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.SubKeyAction
import ai.passman.domain.pgp.model.UserIdAction
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.model.ShareFileKind
import ai.passman.domain.settings.model.ShareFileRequest
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.*
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class PgpKeyDetailsViewModel(
    private val keyId: Long,
    private val getPgpKey: GetPgpKey,
    private val getPgpPublicKeyPath: GetPgpPublicKeyPath,
    private val exportPgpPrivateKey: ExportPgpPrivateKey,
    private val shareFile: ShareFile,
    private val pgpEventPersistence: PgpEventPersistence,
) : BaseViewModel() {
    val navigation = Channel<PgpDetailsNavigation>()
    val userMessages = Channel<String>(Channel.BUFFERED)
    val pgpKey = MutableStateFlow<PgpKeyPair?>(null)

    /** Share or export waiting on the user's confirmation dialog; null when none is pending. */
    val pendingShare = MutableStateFlow<ShareFileRequest?>(null)

    /** True while the export flow is waiting for the key's passphrase. */
    val exportPassphraseRequested = MutableStateFlow(false)

    private var deleteRequested = false

    init {
        viewModelScope.launch {
            val key = getPgpKey(keyId)
            if (key != null) {
                KLogger.i {
                    "key: ${key.publicKey}"
                }
                KLogger.i {
                    "key user ids: ${key.publicKey.userIds}"
                }
                pgpKey.emit(key)
            }
        }

        viewModelScope.launch {
            pgpEventPersistence.events().collect {
                KLogger.i {
                    "pgp event"
                }
                if (!deleteRequested) {
                    getPgpKey(keyId)?.let { pgpKey.emit(it) }
                }
            }
        }
    }

    fun onToolsClicked() = viewModelScope.launch { navigation.send(PgpToolAction(keyId)) }

    fun onAddUserId() = viewModelScope.launch { navigation.send(AddUserId(keyId)) }

    fun onAddSubKey() = viewModelScope.launch { navigation.send(AddSubKey(keyId)) }

    fun onRemoveSubKey(keyIndex: Int) = viewModelScope.launch {
        val subkeyId = pgpKey.value!!.publicKey.subKeys[keyIndex].keyId
        navigation.send(ModifySubKey(keyId, subkeyId.toString(), SubKeyAction.REMOVE))
    }

    fun onRevokeSubKey(keyIndex: Int) = viewModelScope.launch {
        val subkeyId = pgpKey.value!!.publicKey.subKeys[keyIndex].keyId
        navigation.send(ModifySubKey(keyId, subkeyId.toString(), SubKeyAction.REVOKE))
    }

    fun onRevokeUserId(userIdIndex: Int) = viewModelScope.launch {
        val userId = pgpKey.value!!.publicKey.userIds[userIdIndex]
        navigation.send(RevokeUserId(keyId, userId.toString(), UserIdAction.REVOKE))
    }

    fun onRemoveUserId(userIdIndex: Int) = viewModelScope.launch {
        val userId = pgpKey.value!!.publicKey.userIds[userIdIndex]
        navigation.send(RemoveUserId(keyId, userId.toString(), UserIdAction.REMOVE))
    }

    fun onChangeExpirationDate() = viewModelScope.launch { navigation.send(ChangeExpiryKey(keyId)) }

    fun onChangeExpirationDateSub(keyIndex: Int) = viewModelScope.launch { navigation.send(ChangeExpirySubKey(keyId)) }

    fun onChangePassword() = viewModelScope.launch {
        navigation.send(ChangePassword(keyId))
    }

    fun onShareKeyClick() = viewModelScope.launch {
        // Never share publicKey.path directly: when only a secret ring exists for the key it
        // points at the secret-ring file. The use-case resolves a genuine public-ring path or
        // fails, in which case nothing is shared.
        when (val outcome = getPgpPublicKeyPath(keyId)) {
            is Outcome.Success -> pendingShare.emit(
                ShareFileRequest(
                    filePath = outcome.value,
                    displayName = keyDisplayName(),
                    kind = ShareFileKind.PublicKeyOnly,
                )
            )
            is Outcome.Error -> {
                KLogger.e { "share refused, no public key ring file: ${outcome.message}" }
                userMessages.send("Can't share: no standalone public key ring file exists for this key")
            }
        }
    }

    fun onExportPrivateKeyClick() {
        exportPassphraseRequested.value = true
    }

    fun onExportPassphraseDismissed() {
        exportPassphraseRequested.value = false
    }

    fun onExportPassphraseEntered(passphrase: String) {
        exportPassphraseRequested.value = false
        viewModelScope.launch {
            when (val outcome = exportPgpPrivateKey(ExportPgpPrivateKey.Request(keyId, passphrase))) {
                is Outcome.Success -> pendingShare.emit(
                    ShareFileRequest(
                        filePath = outcome.value,
                        displayName = keyDisplayName(),
                        kind = ShareFileKind.PrivateKey,
                    )
                )
                is Outcome.Error -> {
                    KLogger.e { "private key export refused: ${outcome.message}" }
                    userMessages.send(
                        if (outcome.cause == PgpFailure.WrongPassword) {
                            "Wrong passphrase — private key not exported"
                        } else {
                            "Can't export private key: ${outcome.message}"
                        }
                    )
                }
            }
        }
    }

    fun onShareConfirmed() {
        val request = pendingShare.value ?: return
        pendingShare.value = null
        viewModelScope.launch {
            if (!shareFile(request)) {
                userMessages.send("Can't share ${request.displayName}: the file could not be offered")
            }
        }
    }

    fun onShareDismissed() {
        pendingShare.value = null
    }

    /** Blank-guarded display name for share titles and dialogs; also used by the screen. */
    fun keyDisplayName(): String {
        val key = pgpKey.value?.publicKey
        return key?.userIds?.firstOrNull()?.name?.takeIf { it.isNotBlank() }
            ?: key?.fileName?.takeIf { it.isNotBlank() }
            ?: "PGP key"
    }

    fun onDeleteKeyClick() = viewModelScope.launch {
        deleteRequested = true
        navigation.send(KeyDeleted(keyId))
    }
}
