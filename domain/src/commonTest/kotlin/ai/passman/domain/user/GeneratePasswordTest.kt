package ai.passman.domain.user

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class GeneratePasswordTest {
    lateinit var generatePassword: GeneratePassword

    @BeforeTest
    fun setup() {
        generatePassword = GeneratePassword()
    }

    @Test
    fun generatesRequestedLengthFromRequestedCharsetsOnly() = runTest {
        val length = 10
        val password = generatePassword(
            GeneratePassword.PasswordInfo(
                setOf(GeneratePassword.CharSet.UPPERCASE, GeneratePassword.CharSet.NUMBER),
                length,
            ),
        )

        assertEquals(length, password.length)
        // The original commented-out assertion was `!password.contains(SYMBOLS)`, which asks
        // whether the whole 31-character symbol string appears as a substring — trivially
        // true whatever the output. This checks what it meant: no symbol characters at all.
        assertTrue(password.none { it in GeneratePassword.SYMBOLS }, "contained a symbol: $password")
        assertTrue(
            password.all { it in GeneratePassword.UPPER || it in GeneratePassword.NUM },
            "contained a character outside the requested charsets: $password",
        )
    }

    @Test
    fun includesSymbolsWhenRequested() = runTest {
        val password = generatePassword(
            GeneratePassword.PasswordInfo(setOf(GeneratePassword.CharSet.SYMBOLS), 200),
        )

        assertEquals(200, password.length)
        assertTrue(password.all { it in GeneratePassword.SYMBOLS })
    }

    @Test
    fun provisionedSecretShapeIsTypeableAndNeverRepeats() = runTest {
        val alphabet = GeneratePassword.UPPER + GeneratePassword.LOWER +
            GeneratePassword.NUM + GeneratePassword.SYMBOLS

        val first = generatePassword(GeneratePassword.PROVISIONED_SECRET)
        val second = generatePassword(GeneratePassword.PROVISIONED_SECRET)

        assertEquals(24, first.length)
        assertTrue(first.all { it in alphabet }, "every character must be typeable: $first")
        assertTrue(first != second, "a repeated 24-char secret means the random source is broken")
    }

    @Test
    fun aLargeSampleCoversTheWholeAlphabetAndNothingOutsideIt() = runTest {
        // Coverage smoke test, not statistics: at 8192 draws over a 93-character alphabet the
        // chance of any character never appearing is ~e^-88 per character, so a miss means the
        // sampler is broken (e.g. a rejection branch that silently drops part of the range).
        val alphabet = GeneratePassword.UPPER + GeneratePassword.LOWER +
            GeneratePassword.NUM + GeneratePassword.SYMBOLS

        val sample = generatePassword(
            GeneratePassword.PasswordInfo(
                setOf(
                    GeneratePassword.CharSet.UPPERCASE,
                    GeneratePassword.CharSet.LOWERCASE,
                    GeneratePassword.CharSet.NUMBER,
                    GeneratePassword.CharSet.SYMBOLS,
                ),
                8192,
            ),
        )

        assertEquals(8192, sample.length)
        assertTrue(sample.all { it in alphabet }, "a character escaped the alphabet")
        val missing = alphabet.filterNot { it in sample }
        assertTrue(missing.isEmpty(), "characters never produced: '$missing'")
    }

    @Test
    fun returnsEmptyPasswordForZeroLength() = runTest {
        val password = generatePassword(
            GeneratePassword.PasswordInfo(setOf(GeneratePassword.CharSet.LOWERCASE), 0),
        )

        assertEquals("", password)
    }
}
