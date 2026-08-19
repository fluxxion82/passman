package ai.passman.domain.user

import ai.passman.domain.user.ValidateSignUpCredentials.Issue
import ai.passman.domain.user.models.PasswordStrength
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ValidateSignUpCredentialsTest {
    private val validate = ValidateSignUpCredentials()

    @Test
    fun `strong distinct credentials are acceptable`() {
        val result = validate("mia", "correct-Horse-battery-9")
        assertTrue(result.acceptable)
        assertEquals(emptyList(), result.issues)
    }

    @Test
    fun `single character username is rejected`() {
        val result = validate("f", "correct-Horse-battery-9")
        assertEquals(listOf(Issue.UsernameTooShort), result.issues)
    }

    @Test
    fun `username surrounded by whitespace is measured trimmed`() {
        val result = validate("  ab ", "correct-Horse-battery-9")
        assertEquals(listOf(Issue.UsernameTooShort), result.issues)
    }

    @Test
    fun `password below twelve characters is rejected`() {
        val result = validate("mia", "elevenchars")
        assertEquals(listOf(Issue.PasswordTooShort), result.issues)
    }

    @Test
    fun `empty password is rejected as too short`() {
        val result = validate("mia", "")
        assertTrue(Issue.PasswordTooShort in result.issues)
        assertEquals(PasswordStrength.Weak, result.strength)
    }

    @Test
    fun `password containing the username is rejected regardless of case`() {
        val result = validate("Sterling", "mysterlingpass99")
        assertEquals(listOf(Issue.PasswordContainsUsername), result.issues)
    }

    @Test
    fun `containment check uses the trimmed username`() {
        val result = validate(" mia ", "around-mia-padding-42")
        assertEquals(listOf(Issue.PasswordContainsUsername), result.issues)
    }

    @Test
    fun `one repeated character is rejected even when long`() {
        val result = validate("mia", "aaaaaaaaaaaaaaaa")
        assertEquals(listOf(Issue.PasswordSingleCharacter), result.issues)
    }

    @Test
    fun `issues accumulate`() {
        val result = validate("f", "ff")
        assertTrue(Issue.UsernameTooShort in result.issues)
        assertTrue(Issue.PasswordTooShort in result.issues)
        assertFalse(result.acceptable)
    }

    @Test
    fun `twelve lowercase characters rate weak but acceptable`() {
        val result = validate("mia", "qwertzuiopas")
        assertTrue(result.acceptable)
        assertEquals(PasswordStrength.Weak, result.strength)
    }

    @Test
    fun `sixteen lowercase characters rate fair`() {
        val result = validate("mia", "qwertzuiopasdfgh")
        assertEquals(PasswordStrength.Fair, result.strength)
    }

    @Test
    fun `sixteen characters across three classes rate good`() {
        val result = validate("mia", "Qwertzuiopasdfg9")
        assertEquals(PasswordStrength.Good, result.strength)
    }

    @Test
    fun `twenty characters across three classes rate strong`() {
        val result = validate("mia", "Qwertzuiopasdfghjkl9")
        assertEquals(PasswordStrength.Strong, result.strength)
    }

    @Test
    fun `any hard issue caps strength at weak`() {
        val result = validate("mia", "aaaaaaaaaaaaaaaaaaaaaaaa")
        assertEquals(PasswordStrength.Weak, result.strength)
    }
}
