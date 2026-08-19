package ai.passman.viewmodel.home

import ai.passman.domain.keystore.ImportKeystore
import ai.passman.domain.password.GetPasswordEntries
import ai.passman.domain.pgp.ImportPgpKey
import ai.passman.domain.user.LogoutUser
import ai.passman.viewvo.home.HomeNavigation
import io.mockk.coEvery
import io.mockk.mockk
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest

class HomeViewModelTest {
    private val getPasswordEntries: GetPasswordEntries = mockk(relaxed = true)
    private val importPgpKey: ImportPgpKey = mockk(relaxed = true)
    private val importKeystore: ImportKeystore = mockk(relaxed = true)
    private val logoutUser: LogoutUser = mockk(relaxed = true)
    private val homeViewModel = HomeViewModel(importPgpKeys = importPgpKey, importKeystore = importKeystore, logoutUser = logoutUser)

    @BeforeTest
    fun setup() {
        coEvery { getPasswordEntries.invoke(Unit) } returns flowOf()
    }

    @Test
    fun `consecutive nav event test`() = runTest {
        homeViewModel.onPgpClick()

        assertTrue {
            homeViewModel.navigation.receive() == HomeNavigation.PgpTools
        }

        homeViewModel.onPasswordManagement()

        assertTrue {
            homeViewModel.navigation.receive() == HomeNavigation.PasswordManagement
        }
    }
}
