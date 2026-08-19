package ai.passman.domain.pgp

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.exception.PgpFailure
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.test.runTest

class EncryptPgpTest {

    private val cipherText = "-----BEGIN PGP MESSAGE-----"

    @Test
    fun encryptingTextDelegatesToTheRepositoryAndReturnsTheCipherText() = runTest {
        val repository = FakePgpRepository(encrypt = { Outcome.Success(cipherText) })
        val encryptPgp = EncryptPgp(repository)

        val outcome = encryptPgp(
            EncryptPgp.EncryptPgpData.EncryptPgpText("plain text", "path/to/key"),
        )

        assertIs<Outcome.Success<String>>(outcome)
        assertEquals(cipherText, outcome.value)
        assertEquals(listOf("plain text" to "path/to/key"), repository.encryptCalls)
    }

    @Test
    fun encryptingAFileRoutesToTheFileApiRatherThanTheMessageApi() = runTest {
        val repository = FakePgpRepository(encryptFile = { Outcome.Success(cipherText) })
        val encryptPgp = EncryptPgp(repository)

        val outcome = encryptPgp(
            EncryptPgp.EncryptPgpData.EncryptPgpFile("path/to/secret.txt", "path/to/key"),
        )

        assertIs<Outcome.Success<String>>(outcome)
        assertEquals(listOf("path/to/secret.txt" to "path/to/key"), repository.encryptCalls)
    }

    @Test
    fun repositoryFailuresArePropagatedUnchanged() = runTest {
        val repository = FakePgpRepository(
            encrypt = { Outcome.Error("boom", PgpFailure.EncryptFailure) },
        )
        val encryptPgp = EncryptPgp(repository)

        val outcome = encryptPgp(
            EncryptPgp.EncryptPgpData.EncryptPgpText("plain text", "path/to/key"),
        )

        assertIs<Outcome.Error>(outcome)
        assertEquals("boom", outcome.message)
        assertIs<PgpFailure.EncryptFailure>(outcome.cause)
    }
}
