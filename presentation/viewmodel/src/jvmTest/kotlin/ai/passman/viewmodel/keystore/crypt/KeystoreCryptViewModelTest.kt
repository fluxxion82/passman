package ai.passman.viewmodel.keystore.crypt

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.exception.Failure
import ai.passman.domain.keystore.Decrypt
import ai.passman.domain.keystore.Encrypt
import ai.passman.domain.keystore.GetKeystoreKey
import ai.passman.domain.keystore.SignWithKey
import ai.passman.domain.keystore.VerifySignatureKeystore
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.viewmodel.password.SecretPickerResult
import ai.passman.viewmodel.password.applyTo
import androidx.lifecycle.ViewModelStore
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/**
 * The keystore tool screen can fill its key-password field from the vault. Same contract as the PGP
 * side, deliberately asserted separately: the two screens share a design-layer form but not a view
 * model, so "the field only moves on an explicit selection" has to hold in both places on its own.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeystoreCryptViewModelTest {
    private val getKeystoreKey: GetKeystoreKey = mockk(relaxed = true)
    private val encrypt: Encrypt = mockk(relaxed = true)
    private val decrypt: Decrypt = mockk(relaxed = true)
    private val sign: SignWithKey = mockk(relaxed = true)
    private val verifySignatureKeystore: VerifySignatureKeystore = mockk(relaxed = true)
    private val copyToClipboard: CopyToClipboard = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getKeystoreKey.invoke(any()) } returns KeystoreKey(
            keyAlias = "signing",
            keyPassword = "",
            keyAlgorithm = KeystoreKeyAlgorithm.RSA,
        )
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm(action: CryptAction = CryptAction.DECRYPT) = KeystoreCryptViewModel(
        keystorePath = "/keys",
        keystoreName = "ster.p12",
        keyAlias = "signing",
        initialAction = action,
        initialFileTarget = false,
        getKeystoreKey = getKeystoreKey,
        encrypt = encrypt,
        decrypt = decrypt,
        sign = sign,
        verifySignatureKeystore = verifySignatureKeystore,
        copyToClipboard = copyToClipboard,
    )

    @Test
    fun `keystore tools always offer all crypt actions`() = runTest {
        val vm = newVm()

        assertEquals(CryptAction.entries.toList(), vm.availableActions.value)
    }

    @Test
    fun `selecting an action clears text and signature inputs along with the previous crypt result and error`() = runTest {
        val vm = newVm()
        vm.inputText.value = "old ciphertext"
        vm.inputSignatureData.value = "old signature"
        vm.outputData.value = "old result"
        vm.isError.value = true
        vm.errorMessage.value = "old error"

        vm.onActionSelected(CryptAction.ENCRYPT)

        assertEquals(CryptAction.ENCRYPT, vm.action.value)
        assertEquals("", vm.inputText.value)
        assertEquals("", vm.inputSignatureData.value)
        assertEquals("", vm.outputData.value)
        assertEquals(false, vm.isError.value)
        assertEquals(null, vm.errorMessage.value)
    }

    @Test
    fun `changing between text and file clears text and signature inputs along with the previous crypt result and error`() = runTest {
        val vm = newVm()
        vm.inputText.value = "old ciphertext"
        vm.inputSignatureData.value = "old signature"
        vm.outputData.value = "old result"
        vm.isError.value = true
        vm.errorMessage.value = "old error"

        vm.onTargetToggle(true)

        assertEquals(true, vm.isFileTarget.value)
        assertEquals("", vm.inputText.value)
        assertEquals("", vm.inputSignatureData.value)
        assertEquals("", vm.outputData.value)
        assertEquals(false, vm.isError.value)
        assertEquals(null, vm.errorMessage.value)
    }

    @Test
    fun `a failed decrypt shows its message and falls back to an action sentence when blank`() = runTest {
        coEvery { decrypt.invoke(any()) } returns Outcome.Error("wrong passphrase", Failure.NetworkConnection())
        val vm = newVm()

        vm.onActionClick()

        assertEquals(true, vm.isError.value)
        assertEquals("wrong passphrase", vm.errorMessage.value)
        assertEquals("", vm.outputData.value)

        coEvery { decrypt.invoke(any()) } returns Outcome.Error("", Failure.NetworkConnection())

        vm.onActionClick()

        assertEquals("Decryption failed.", vm.errorMessage.value)
    }

    @Test
    fun `editing input or password clears the crypt error message`() = runTest {
        coEvery { decrypt.invoke(any()) } returns Outcome.Error("wrong passphrase", Failure.NetworkConnection())
        val vm = newVm()

        vm.onActionClick()
        vm.onInputTextChanged("corrected ciphertext")

        assertEquals(false, vm.isError.value)
        assertEquals(null, vm.errorMessage.value)

        vm.onActionClick()
        vm.onPasswordChanged("corrected password")

        assertEquals(false, vm.isError.value)
        assertEquals(null, vm.errorMessage.value)
    }

    @Test
    fun `a picked saved password replaces whatever was typed in the alias password field`() = runTest {
        val vm = newVm()
        vm.onPasswordChanged("typed-by-hand")

        SecretPickerResult.Selected("keystore-vault-secret").applyTo(vm::onPasswordChanged)

        assertEquals("keystore-vault-secret", vm.aliasPassword.value)
    }

    /**
     * The negative that matters: backing out of the picker is not an edit. A cancel that blanked
     * the alias password would silently break the next signing run with a wrong-password error the
     * user had no reason to expect.
     */
    @Test
    fun `cancelling the picker leaves the typed alias password exactly as it was`() = runTest {
        val vm = newVm()
        vm.onPasswordChanged("typed-by-hand")

        SecretPickerResult.Cancelled.applyTo(vm::onPasswordChanged)

        assertEquals("typed-by-hand", vm.aliasPassword.value)
    }

    /** Cancelling after a fill must not undo the fill either. */
    @Test
    fun `cancelling a second picker session leaves the filled alias password in place`() = runTest {
        val vm = newVm(action = CryptAction.SIGN)
        SecretPickerResult.Selected("first-choice").applyTo(vm::onPasswordChanged)

        SecretPickerResult.Cancelled.applyTo(vm::onPasswordChanged)

        assertEquals("first-choice", vm.aliasPassword.value)
    }

    @Test
    fun `onCleared drops the alias password the picker filled in`() = runTest {
        val vm = newVm()
        SecretPickerResult.Selected("keystore-vault-secret").applyTo(vm::onPasswordChanged)
        assertEquals("keystore-vault-secret", vm.aliasPassword.value)

        ViewModelStore().apply { put("keystore-crypt", vm) }.clear()

        assertEquals("", vm.aliasPassword.value)
    }

    @Test
    fun `onCleared drops a hand-typed alias password too`() = runTest {
        val vm = newVm(action = CryptAction.ENCRYPT_AND_SIGN)
        vm.onPasswordChanged("typed-by-hand")

        ViewModelStore().apply { put("keystore-crypt", vm) }.clear()

        assertEquals("", vm.aliasPassword.value)
    }

    @Test
    fun `filling the field from the vault never touches the clipboard`() = runTest {
        val vm = newVm()

        SecretPickerResult.Selected("keystore-vault-secret").applyTo(vm::onPasswordChanged)

        coVerify(exactly = 0) { copyToClipboard.invoke(any()) }
    }

    /**
     * The layer rule, pinned structurally — see the PGP twin for the reasoning. `String` is allowed
     * because this screen is addressed by keystore path, name and alias.
     */
    @Test
    fun `the crypt view model is built from domain use cases only`() {
        // Synthetics are the compiler's default-argument bridges, not the declared surface.
        val parameterTypes = KeystoreCryptViewModel::class.java.declaredConstructors
            .filterNot { it.isSynthetic }
            .single()
            .parameterTypes

        val foreign = parameterTypes.filterNot {
            it.isPrimitive || it == String::class.java || it.name.startsWith("ai.passman.domain.")
        }

        assertEquals(emptyList(), foreign.map { it.name })
    }
}
