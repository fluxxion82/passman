package ai.passman.domain.pgp

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.exception.PgpFailure
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.test.runTest

class DecryptPgpTest {

    private val plainText = "plain text"

    @Test
    fun decryptingTextPassesTheKeyPathAndPasswordThrough() = runTest {
        val repository = FakePgpRepository(decrypt = { Outcome.Success(plainText) })
        val decryptPgp = DecryptPgp(repository)

        val outcome = decryptPgp(
            DecryptPgp.DecryptPgpData.DecryptPgpText("cipher", "/path/to/key", "password"),
        )

        assertIs<Outcome.Success<String>>(outcome)
        assertEquals(plainText, outcome.value)
        assertEquals(
            listOf(Triple("cipher", "/path/to/key", "password")),
            repository.decryptCalls,
        )
    }

    @Test
    fun decryptingAFileRoutesToTheFileApiRatherThanTheMessageApi() = runTest {
        val repository = FakePgpRepository(decryptFile = { Outcome.Success(plainText) })
        val decryptPgp = DecryptPgp(repository)

        val outcome = decryptPgp(
            DecryptPgp.DecryptPgpData.DecryptPgpFile("/path/to/secret.gpg", "/path/to/key", "password"),
        )

        assertIs<Outcome.Success<String>>(outcome)
        assertEquals(
            listOf(Triple("/path/to/secret.gpg", "/path/to/key", "password")),
            repository.decryptCalls,
        )
    }

    @Test
    fun wrongPasswordFailuresArePropagatedUnchanged() = runTest {
        val repository = FakePgpRepository(
            decrypt = { Outcome.Error("wrong password", PgpFailure.WrongPassword) },
        )
        val decryptPgp = DecryptPgp(repository)

        val outcome = decryptPgp(
            DecryptPgp.DecryptPgpData.DecryptPgpText("cipher", "/path/to/key", "nope"),
        )

        assertIs<Outcome.Error>(outcome)
        assertEquals("wrong password", outcome.message)
        assertIs<PgpFailure.WrongPassword>(outcome.cause)
    }
}
