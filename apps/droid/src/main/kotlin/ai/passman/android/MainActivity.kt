package ai.passman.android

import ai.passman.design.PassmanTheme
import ai.passman.design.crypt.CryptoToolContent
import ai.passman.design.crypt.model.ToolSet
import ai.passman.screens.ui.PassMan
import ai.passman.domain.base.invoke
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.model.UserId
import ai.passman.domain.settings.GetThemeMode
import ai.passman.domain.settings.model.ThemeMode
import android.annotation.SuppressLint
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.tooling.preview.Preview
import androidx.core.view.WindowInsetsControllerCompat
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.koin.android.ext.android.inject

@InternalCoroutinesApi
class MainActivity : AppCompatActivity() {
    private val getThemeMode: GetThemeMode by inject()

    override fun onCreate(savedInstanceState: Bundle?) {
        // The stored mode is read synchronously and the night mode set before super.onCreate,
        // so the DayNight window background resolves right the first time. Driving
        // setDefaultNightMode from composition state recreated the activity, which reset the
        // state to System before the async read landed — an endless recreate/flash loop.
        val initialMode = runBlocking { getThemeMode() }
        AppCompatDelegate.setDefaultNightMode(initialMode.toNightMode())
        super.onCreate(savedInstanceState)
        window.apply {
            setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        }
        enableEdgeToEdge()

        setContent {
            var themeMode by remember { mutableStateOf(initialMode) }
            val systemDarkTheme = isSystemInDarkTheme()
            val darkTheme = when (themeMode) {
                ThemeMode.System -> systemDarkTheme
                ThemeMode.Light -> false
                ThemeMode.Dark -> true
            }
            SideEffect {
                WindowInsetsControllerCompat(window, window.decorView).isAppearanceLightStatusBars = !darkTheme
            }
            PassmanTheme(themeMode = themeMode) {
                // A live change re-themes Compose only; the window background catches up on
                // the next launch. Calling setDefaultNightMode here would recreate the
                // activity mid-session and race the preference write.
                MyApp(onThemeModeChanged = { themeMode = it })
            }
        }
    }

    private fun ThemeMode.toNightMode(): Int = when (this) {
        ThemeMode.System -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        ThemeMode.Light -> AppCompatDelegate.MODE_NIGHT_NO
        ThemeMode.Dark -> AppCompatDelegate.MODE_NIGHT_YES
    }

    @SuppressLint("UnusedMaterialScaffoldPaddingParameter")
    @OptIn(ExperimentalFoundationApi::class)
    @Composable
    fun MyApp(onThemeModeChanged: (ThemeMode) -> Unit) {
        PassMan(onThemeModeChanged = onThemeModeChanged)
    }
}

@Preview
@Composable
fun PreviewCryptoFile() {
    CryptoToolContent(
        toolSet = ToolSet.PGP,
        action = CryptAction.DECRYPT,
        keyAlgorithm = KeystoreKeyAlgorithm.RSA,
        isFileTarget = true,
        keyName = "key one",
        keyAlias = "",
        userIds = listOf("joe <hoe@svd.com>"),
        password = "",
        selectedUserId = "joe <hoe@svd.com>",
        filePath = "",
        inputData = "asdfsad",
        inputSignatureData = "",
        useSalt = false,
        saltIv = "",
        outputData = "asdfasdf",
        isLoading = true,
        isError = false,
        regenSalt = {},
        onUserIdSelected = {},
        onFilePathSelected = {},
        onTextChanged = {},
        onInputSignatureChanged = {},
        onSaltIvChanged = {},
        onSaltIvChecked = {},
        onPasswordChanged = {},
        onExecuteAction = {},
        onCopyClicked = {},
    )
}

@Preview
@Composable
fun PreviewCryptoText() {
    CryptoToolContent(
        toolSet = ToolSet.PGP,
        action = CryptAction.ENCRYPT,
        keyAlgorithm = KeystoreKeyAlgorithm.RSA,
        isFileTarget = false,
        keyName = "key one",
        keyAlias = "",
        userIds = listOf("joe <hoe@svd.com>"),
        password = "",
        selectedUserId = "joe <hoe@svd.com>",
        filePath = "",
        inputData = "asdfsad",
        inputSignatureData = "",
        useSalt = false,
        saltIv = "",
        outputData = "asdfasdf",
        isLoading = false,
        isError = false,
        regenSalt = {},
        onUserIdSelected = {},
        onFilePathSelected = {},
        onTextChanged = {},
        onInputSignatureChanged = {},
        onSaltIvChanged = {},
        onSaltIvChecked = {},
        onPasswordChanged = {},
        onExecuteAction = {},
        onCopyClicked = {},
    )
}

//@Preview
//@Composable
//fun PreviewPgpKeyDisplay() {
//    PgpKeyDisplay(
//        getKeyPair(),
//        onToolsClicked = {},
//        onAddUserId = {},
//        onAddSubKey = {},
//        onRemoveUserId = {},
//        onRemoveSubKey = {},
//        onRevokeSubKey = {},
//        onRevokeUserId = {},
//        onChangeExpirationDate = {},
//        onChangeExpirationDateSub = {},
//        onChangePassword = {},
//    )
//}
//
//@Preview
//@Composable
//fun PreviewSubKeyDetails() {
//    SubKeyDetails(keyPair = getKeyPair(), {}, {}, {}, {})
//}

private fun getKeyPair() =
    PgpKeyPair(
        publicKey = PgpKey(
            fileName = "my key",
            path = "/path/to/keyfile",
            type = PgpKeyType.Public,
            keyId = -8880064556829350367,
            creationTime = System.currentTimeMillis(),
            expirationTime = System.currentTimeMillis() + 1000000000,
            isRevoked = false,
            algorithm = "RSA",
            bitStrength = 2048,
            userIds = listOf(UserId(name = "test", email ="user@example.com", isRevoked = false)),
            fingerprint = "ABC123DEF456GHI789J",
            isMaster = true,
            isEncryptionKey = true,
            isSigningKey = true,
            subKeys = listOf(
                PgpKey(
                    fileName = "my key",
                    path = "/path/to/subkeyfile",
                    type = PgpKeyType.Secret,
                    keyId = -8880064556829350367,
                    creationTime = System.currentTimeMillis(),
                    expirationTime = null,
                    isRevoked = true,
                    algorithm = "RSA",
                    bitStrength = 1024,
                    userIds = listOf(UserId(name = "test", email ="user@example.com", isRevoked = false)),
                    fingerprint = "XYZ987UTS456ABC123",
                    isMaster = false,
                    isEncryptionKey = true,
                    isSigningKey = false
                )
            )
        ),
        secretKey = PgpKey(
            fileName = "my key two",
            path = "/path/to/keyfile",
            type = PgpKeyType.Public,
            keyId = -8880064556829350367,
            creationTime = System.currentTimeMillis(),
            expirationTime = System.currentTimeMillis() + 1000000000,
            isRevoked = false,
            algorithm = "RSA",
            bitStrength = 2048,
            userIds = listOf(UserId(name = "test", email ="user@example.com", isRevoked = false)),
            fingerprint = "ABC123DEF456GHI789J",
            isMaster = true,
            isEncryptionKey = true,
            isSigningKey = true,
            subKeys = listOf(
                PgpKey(
                    fileName = "my key two",
                    path = "/path/to/subkeyfile",
                    type = PgpKeyType.Secret,
                    keyId = -8880064556829350367,
                    creationTime = System.currentTimeMillis(),
                    expirationTime = null,
                    isRevoked = true,
                    algorithm = "RSA",
                    bitStrength = 1024,
                    userIds = listOf(UserId(name = "test", email ="user@example.com", isRevoked = false)),
                    fingerprint = "XYZ987UTS456ABC123",
                    isMaster = false,
                    isEncryptionKey = true,
                    isSigningKey = false
                )
            )
        )
    )
