package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.ExportPgpPrivateKey
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.GetPgpPublicKeyPath
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.model.UserId
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.model.ShareFileKind
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/**
 * Pins the share/export contract: nothing leaves the app without the user confirming a staged
 * request, share failures surface as user messages instead of silence, and private-key export is
 * gated behind a passphrase the domain layer verifies.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PgpKeyDetailsViewModelTest {
    private val getPgpKey: GetPgpKey = mockk(relaxed = true)
    private val getPgpPublicKeyPath: GetPgpPublicKeyPath = mockk(relaxed = true)
    private val exportPgpPrivateKey: ExportPgpPrivateKey = mockk(relaxed = true)
    private val shareFile: ShareFile = mockk(relaxed = true)
    private val pgpEventPersistence: PgpEventPersistence = mockk()

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getPgpKey.invoke(any()) } returns keyPair()
        every { pgpEventPersistence.events() } returns emptyFlow()
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = PgpKeyDetailsViewModel(
        keyId = 42L,
        getPgpKey = getPgpKey,
        getPgpPublicKeyPath = getPgpPublicKeyPath,
        exportPgpPrivateKey = exportPgpPrivateKey,
        shareFile = shareFile,
        pgpEventPersistence = pgpEventPersistence,
    )

    private fun keyPair(): PgpKeyPair {
        val publicKey = PgpKey(
            fileName = "ada_public_ring.asc",
            path = "/keys/ada_public_ring.asc",
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
                fileName = "ada_secret_ring.asc",
                path = "/keys/ada_secret_ring.asc",
                type = PgpKeyType.Secret,
            ),
        )
    }

    @Test
    fun `share click stages a public-key-only request and nothing leaves before confirmation`() = runTest {
        coEvery { getPgpPublicKeyPath.invoke(42L) } returns Outcome.Success("/keys/ada_public_ring.asc")
        val vm = newVm()

        vm.onShareKeyClick()

        val staged = assertNotNull(vm.pendingShare.value)
        assertEquals("/keys/ada_public_ring.asc", staged.filePath)
        assertEquals(ShareFileKind.PublicKeyOnly, staged.kind)
        coVerify(exactly = 0) { shareFile.invoke(any()) }

        vm.onShareConfirmed()

        coVerify(exactly = 1) { shareFile.invoke(staged) }
        assertNull(vm.pendingShare.value)
    }

    @Test
    fun `a failed public key path lookup surfaces a user message instead of silence`() = runTest {
        coEvery { getPgpPublicKeyPath.invoke(42L) } returns
            Outcome.Error("no public key ring file for key", PgpFailure.SharePublicKeyFailure)
        val vm = newVm()

        vm.onShareKeyClick()

        assertNotNull(vm.userMessages.tryReceive().getOrNull())
        assertNull(vm.pendingShare.value)
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }

    @Test
    fun `export asks for the passphrase and stages a private-key share once the unlock succeeds`() = runTest {
        coEvery { exportPgpPrivateKey.invoke(ExportPgpPrivateKey.Request(42L, "hunter2")) } returns
            Outcome.Success("/keys/ada_secret_ring.asc")
        val vm = newVm()

        vm.onExportPrivateKeyClick()
        assertEquals(true, vm.exportPassphraseRequested.value)

        vm.onExportPassphraseEntered("hunter2")

        assertEquals(false, vm.exportPassphraseRequested.value)
        val staged = assertNotNull(vm.pendingShare.value)
        assertEquals("/keys/ada_secret_ring.asc", staged.filePath)
        assertEquals(ShareFileKind.PrivateKey, staged.kind)
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }

    @Test
    fun `a wrong export passphrase surfaces a message and stages nothing`() = runTest {
        coEvery { exportPgpPrivateKey.invoke(any()) } returns
            Outcome.Error("wrong passphrase", PgpFailure.WrongPassword)
        val vm = newVm()

        vm.onExportPrivateKeyClick()
        vm.onExportPassphraseEntered("wrong")

        val message = assertNotNull(vm.userMessages.tryReceive().getOrNull())
        assertTrue(message.contains("Wrong passphrase"), "got: $message")
        assertNull(vm.pendingShare.value)
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }

    @Test
    fun `dismissing the confirmation drops the pending share`() = runTest {
        coEvery { getPgpPublicKeyPath.invoke(42L) } returns Outcome.Success("/keys/ada_public_ring.asc")
        val vm = newVm()
        vm.onShareKeyClick()

        vm.onShareDismissed()

        assertNull(vm.pendingShare.value)
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }
}
