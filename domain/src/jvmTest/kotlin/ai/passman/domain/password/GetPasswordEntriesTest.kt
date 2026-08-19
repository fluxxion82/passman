package ai.passman.domain.password

import ai.passman.domain.base.invoke
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository
import io.mockk.MockKAnnotations
import io.mockk.coEvery
import io.mockk.impl.annotations.MockK
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest

class GetPasswordEntriesTest {

    private lateinit var usecase: GetPasswordEntries

    @MockK
    private lateinit var passwordRepository: PasswordRepository

    @MockK
    private lateinit var passwordEventPersistence: PasswordEventPersistence


    @BeforeTest
    fun setup() {
        MockKAnnotations.init(this)
        usecase = GetPasswordEntries(passwordRepository, passwordEventPersistence)
    }


    @Test
    fun get_password_entries_sorted_by_name() = runTest {
        coEvery { passwordEventPersistence.events() } returns flowOf()
        coEvery {
            passwordRepository.getPasswordEntries()
        } returns listOf(
            PasswordEntry(id = "1", entryName = "gmail", "joe", "safsd", "", "", 42314L),
            PasswordEntry(id = "2", entryName = "coinbase", "joe", "safsd", "", "", 42314L),
            PasswordEntry(id = "3", entryName = "TSA", "joe", "safsd", "", "", 42314L),
        )

        val returnedList = usecase().first()

        returnedList.forEach {
            println("${it.entryName}")
        }
        assertTrue {
            returnedList.first().entryName == "coinbase"
        }
    }
}
