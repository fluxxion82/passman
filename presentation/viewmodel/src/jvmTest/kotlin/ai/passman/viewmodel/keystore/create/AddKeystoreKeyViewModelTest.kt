package ai.passman.viewmodel.keystore.create

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.AddKeystoreKey
import ai.passman.domain.keystore.GetKeystore
import ai.passman.domain.password.AddPassword
import ai.passman.domain.user.exception.AuthFailure
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

@OptIn(ExperimentalCoroutinesApi::class)
class AddKeystoreKeyViewModelTest {
    private val getKeystore: GetKeystore = mockk(relaxed = true)
    private val addKeystoreKey: AddKeystoreKey = mockk(relaxed = true)
    private val addPassword: AddPassword = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(StandardTestDispatcher())
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    /** Adding a key runs a slow keygen; a double-tap must not mint two keys. */
    @Test
    fun `a second add click while one is in flight is ignored`() = runTest {
        coEvery { addKeystoreKey.invoke(any()) } coAnswers {
            delay(5_000)
            Outcome.Error("boom", AuthFailure.KeystoreCreationFailure)
        }

        val vm = AddKeystoreKeyViewModel(
            keystorePath = "/tmp/store.pfx",
            keystoreName = "store",
            getKeystore = getKeystore,
            addKeystoreKey = addKeystoreKey,
            addPassword = addPassword,
        )
        runCurrent()
        vm.onAddKeyClick()
        runCurrent()
        vm.onAddKeyClick()
        runCurrent()

        advanceUntilIdle()
        coVerify(exactly = 1) { addKeystoreKey.invoke(any()) }
    }
}
