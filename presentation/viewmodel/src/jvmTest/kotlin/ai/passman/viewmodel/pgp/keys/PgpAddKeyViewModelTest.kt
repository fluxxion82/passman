package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.AddPassword
import ai.passman.domain.pgp.CreatePgpKeyPair
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
class PgpAddKeyViewModelTest {
    private val createPgpKey: CreatePgpKeyPair = mockk(relaxed = true)
    private val addPassword: AddPassword = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(StandardTestDispatcher())
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    /**
     * RSA-4096 generation takes seconds — the widest double-tap window in the app. The existing
     * isLoading flag flipped inside the coroutine, which leaves a race before it runs; the guard
     * has to trip synchronously on the click.
     */
    @Test
    fun `a second create click while keygen is in flight is ignored`() = runTest {
        coEvery { createPgpKey.invoke(any()) } coAnswers {
            delay(5_000)
            Outcome.Error("boom", AuthFailure.PgpKeyRingCreationFailure)
        }

        val vm = PgpAddKeyViewModel(createPgpKey = createPgpKey, addPassword = addPassword)
        vm.onCreateSubkeyClick()
        vm.onCreateSubkeyClick()
        runCurrent()

        advanceUntilIdle()
        coVerify(exactly = 1) { createPgpKey.invoke(any()) }
    }
}
