package ai.passman.viewmodel.pgp.crypt

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.pgp.ClearSignPgp
import ai.passman.domain.pgp.DecryptAndVerify
import ai.passman.domain.pgp.DecryptPgp
import ai.passman.domain.pgp.EncryptAndSignPgp
import ai.passman.domain.pgp.EncryptPgp
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.VerifyClearSignature
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.model.UserId
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
 * The PGP tool screen can fill its key-password field from the vault. This pins the half of that
 * contract the view model owns: the field moves on an explicit selection and on nothing else, and
 * the secret does not outlive the screen.
 *
 * The picker itself is deliberately absent from this view model's surface — see
 * [`the crypt view model is built from domain use cases only`]. The screen collects the picker's
 * one-shot result and routes it through [applyTo] into the same `onPasswordChanged` setter the
 * keyboard uses, so the routing tested here is the production routing.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PgpCryptViewModelTest {
    private val getPgpKey: GetPgpKey = mockk(relaxed = true)
    private val encryptPgp: EncryptPgp = mockk(relaxed = true)
    private val encryptAndSignPgp: EncryptAndSignPgp = mockk(relaxed = true)
    private val decryptPgp: DecryptPgp = mockk(relaxed = true)
    private val clearSign: ClearSignPgp = mockk(relaxed = true)
    private val decryptAndVerifyPgp: DecryptAndVerify = mockk(relaxed = true)
    private val verifyClearSignature: VerifyClearSignature = mockk(relaxed = true)
    private val copyToClipboard: CopyToClipboard = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getPgpKey.invoke(any()) } returns null
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm(action: CryptAction = CryptAction.DECRYPT) = PgpCryptViewModel(
        keyId = 42L,
        initialAction = action,
        initialFileTarget = false,
        getPgpKey = getPgpKey,
        encryptPgp = encryptPgp,
        encryptAndSignPgp = encryptAndSignPgp,
        decryptPgp = decryptPgp,
        clearSign = clearSign,
        decryptAndVerifyPgp = decryptAndVerifyPgp,
        verifyClearSignature = verifyClearSignature,
        copyToClipboard = copyToClipboard,
    )

    private fun keyPair(withSecretKey: Boolean): PgpKeyPair {
        val publicKey = PgpKey(
            fileName = "public.asc",
            path = "/keys/public.asc",
            type = PgpKeyType.Public,
            keyId = 42L,
            creationTime = 0L,
            expirationTime = null,
            isRevoked = false,
            algorithm = "RSA",
            bitStrength = 4096,
            userIds = listOf(UserId(name = "Ada", email = "ada@example.com", isRevoked = false)),
            fingerprint = "ABCD",
            isMaster = true,
            isSigningKey = true,
            isEncryptionKey = true,
        )
        return PgpKeyPair(
            publicKey = publicKey,
            secretKey = publicKey.copy(
                fileName = "secret.asc",
                path = "/keys/secret.asc",
                type = PgpKeyType.Secret,
            ).takeIf { withSecretKey },
        )
    }

    @Test
    fun `public keys offer encrypt and verify while secret keys offer all crypt actions`() = runTest {
        coEvery { getPgpKey.invoke(any()) } returns keyPair(withSecretKey = false)
        val publicKeyVm = newVm()

        assertEquals(listOf(CryptAction.ENCRYPT, CryptAction.VERIFY), publicKeyVm.availableActions.value)

        coEvery { getPgpKey.invoke(any()) } returns keyPair(withSecretKey = true)
        val secretKeyVm = newVm()

        assertEquals(CryptAction.entries.toList(), secretKeyVm.availableActions.value)
    }

    @Test
    fun `selecting an action clears input along with the previous crypt result and error`() = runTest {
        val vm = newVm()
        vm.inputText.value = "old ciphertext"
        vm.outputText.value = "old result"
        vm.isError.value = true
        vm.errorMessage.value = "old error"

        vm.onActionSelected(CryptAction.ENCRYPT)

        assertEquals(CryptAction.ENCRYPT, vm.action.value)
        assertEquals("", vm.inputText.value)
        assertEquals("", vm.outputText.value)
        assertEquals(false, vm.isError.value)
        assertEquals(null, vm.errorMessage.value)
    }

    @Test
    fun `changing between text and file clears input along with the previous crypt result and error`() = runTest {
        val vm = newVm()
        vm.inputText.value = "old ciphertext"
        vm.outputText.value = "old result"
        vm.isError.value = true
        vm.errorMessage.value = "old error"

        vm.onTargetToggle(true)

        assertEquals(true, vm.isFileTarget.value)
        assertEquals("", vm.inputText.value)
        assertEquals("", vm.outputText.value)
        assertEquals(false, vm.isError.value)
        assertEquals(null, vm.errorMessage.value)
    }

    @Test
    fun `a failed decrypt shows its message and falls back to an action sentence when blank`() = runTest {
        coEvery { getPgpKey.invoke(any()) } returns keyPair(withSecretKey = true)
        coEvery { decryptPgp.invoke(any()) } returns Outcome.Error("wrong passphrase", PgpFailure.WrongPassword)
        val vm = newVm()

        vm.onActionClick()

        assertEquals(true, vm.isError.value)
        assertEquals("wrong passphrase", vm.errorMessage.value)
        assertEquals("", vm.outputText.value)

        coEvery { decryptPgp.invoke(any()) } returns Outcome.Error("", PgpFailure.WrongPassword)

        vm.onActionClick()

        assertEquals("Decryption failed.", vm.errorMessage.value)
    }

    @Test
    fun `editing input or password clears the crypt error message`() = runTest {
        coEvery { getPgpKey.invoke(any()) } returns keyPair(withSecretKey = true)
        coEvery { decryptPgp.invoke(any()) } returns Outcome.Error("wrong passphrase", PgpFailure.WrongPassword)
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
    fun `a picked saved password replaces whatever was typed in the key password field`() = runTest {
        val vm = newVm()
        vm.onPasswordChanged("typed-by-hand")

        SecretPickerResult.Selected("pgp-vault-secret").applyTo(vm::onPasswordChanged)

        assertEquals("pgp-vault-secret", vm.keyPassword.value)
    }

    /**
     * The negative that matters. A user who opens the picker, sees nothing useful and backs out
     * still has whatever they had typed — a cancel that blanked the field, or that quietly wrote
     * some other entry's password into it, would be the worst possible failure mode for a decrypt
     * form.
     */
    @Test
    fun `cancelling the picker leaves the typed key password exactly as it was`() = runTest {
        val vm = newVm()
        vm.onPasswordChanged("typed-by-hand")

        SecretPickerResult.Cancelled.applyTo(vm::onPasswordChanged)

        assertEquals("typed-by-hand", vm.keyPassword.value)
    }

    /** Cancelling after a fill must not undo the fill either. */
    @Test
    fun `cancelling a second picker session leaves the filled key password in place`() = runTest {
        val vm = newVm(action = CryptAction.SIGN)
        SecretPickerResult.Selected("first-choice").applyTo(vm::onPasswordChanged)

        SecretPickerResult.Cancelled.applyTo(vm::onPasswordChanged)

        assertEquals("first-choice", vm.keyPassword.value)
    }

    /**
     * The picker's own result flow does not replay, so nothing is left holding the secret there.
     * The field is the copy that *does* persist for as long as the screen does, so the screen going
     * away has to take it with it.
     */
    @Test
    fun `onCleared drops the key password the picker filled in`() = runTest {
        val vm = newVm()
        SecretPickerResult.Selected("pgp-vault-secret").applyTo(vm::onPasswordChanged)
        assertEquals("pgp-vault-secret", vm.keyPassword.value)

        ViewModelStore().apply { put("pgp-crypt", vm) }.clear()

        assertEquals("", vm.keyPassword.value)
    }

    @Test
    fun `onCleared drops a hand-typed key password too`() = runTest {
        val vm = newVm(action = CryptAction.DECRYPT_AND_VERIFY)
        vm.onPasswordChanged("typed-by-hand")

        ViewModelStore().apply { put("pgp-crypt", vm) }.clear()

        assertEquals("", vm.keyPassword.value)
    }

    /**
     * Filling from the vault must not become a second way to put a secret on the clipboard. The
     * picker takes no clipboard dependency at all (pinned in `SecretPickerViewModelTest`); this
     * pins the other end, that routing a selection into the field copies nothing.
     */
    @Test
    fun `filling the field from the vault never touches the clipboard`() = runTest {
        val vm = newVm()

        SecretPickerResult.Selected("pgp-vault-secret").applyTo(vm::onPasswordChanged)

        coVerify(exactly = 0) { copyToClipboard.invoke(any()) }
    }

    /**
     * The layer rule, pinned structurally: this view model is assembled from domain use cases and
     * plain values only. It fails if anyone injects a data-layer type, and — the reason it exists
     * here — if anyone hands the crypt view model the picker itself. The picker is screen state,
     * and a view model that owned one would own a live vault feed and a delivered password.
     */
    @Test
    fun `the crypt view model is built from domain use cases only`() {
        // Synthetics are the compiler's default-argument bridges, not the declared surface.
        val parameterTypes = PgpCryptViewModel::class.java.declaredConstructors
            .filterNot { it.isSynthetic }
            .single()
            .parameterTypes

        val foreign = parameterTypes.filterNot {
            it.isPrimitive || it == String::class.java || it.name.startsWith("ai.passman.domain.")
        }

        assertEquals(emptyList(), foreign.map { it.name })
    }
}
