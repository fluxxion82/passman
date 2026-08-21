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
        assertEquals([Issue.UsernameTooShort], result.issues)
    }

    @Test
    fun `username surrounded by whitespace is measured trimmed`() {
        val result = validate("  ab ", "correct-Horse-battery-9")
        assertEquals([Issue.UsernameTooShort], result.issues)
    }

    @Test
    fun `password below twelve characters is rejected`() {
        val result = validate("mia", "elevenchars")
        assertEquals([Issue.PasswordTooShort], result.issues)
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
        assertEquals([Issue.PasswordContainsUsername], result.issues)
    }

    @Test
    fun `containment check uses the trimmed username`() {
        val result = validate(" mia ", "around-mia-padding-42")
        assertEquals([Issue.PasswordContainsUsername], result.issues)
    }

    @Test
    fun `one repeated character is rejected even when long`() {
        val result = validate("mia", "aaaaaaaaaaaaaaaa")
        assertEquals([Issue.PasswordSingleCharacter], result.issues)
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

    /**
     * The username is a path component, so a username that is really a path is refused.
     *
     * Each of these broke something downstream, found by a separate round of adversarial review, and
     * all of them were the same bug. `./alice` and `team/a` made the sync exclusion list — which
     * compares basenames — miss the account's own identity store, so an inbound bundle replaced the
     * RSA key the vault is sealed under. `team/a` additionally nested one account's directory inside
     * another's, so two accounts held different locks over one set of files. `alice.lock` claims the
     * path account `alice` uses for its lock file.
     *
     * Refusing them at sign-up is the one rule that removes the class; guarding each consequence
     * separately did not converge.
     */
    @Test
    fun refusesAUsernameThatIsReallyAPath() {
        listOf(
            "./alice",
            "team/a",
            // Not ".." itself: at two characters it is refused as too short before the character
            // check is even consulted, which is gated on the length rule the way
            // PasswordContainsUsername already is. "..a" is the same shape at a legal length.
            "..a",
            "a/b",
            "a\\b",
            ".alice",
            "alice.",
            "a<b",
            "a:b",
            "a|b",
        ).forEach { username ->
            val result = validate(username, STRONG_PASSWORD)
            assertTrue(
                Issue.UsernameHasIllegalCharacters in result.issues,
                "\"$username\" is not usable as a directory name and must be refused",
            )
            assertFalse(result.acceptable)
        }
    }

    /**
     * Surrounding whitespace is trimmed, not refused — and that is only safe because the name that
     * gets *stored* is trimmed the same way.
     *
     * `SignUpUser` persists `param.username.trim()`, and this validator judges `username.trim()`. If
     * those two ever disagreed, a name this accepts as `alice` would be created as `alice `, whose
     * trailing space Windows folds away — the account would resolve onto a different one's paths.
     * The agreement is the load-bearing part; the trimming itself is a convenience.
     */
    @Test
    fun trimsSurroundingWhitespaceRatherThanRefusingIt() {
        val result = validate("  alice  ", STRONG_PASSWORD)

        assertFalse(
            Issue.UsernameHasIllegalCharacters in result.issues,
            "a name that trims to something legal is legal",
        )
        assertTrue(result.acceptable)
    }

    /**
     * Non-ASCII is refused, and the reason is normalisation rather than parochialism.
     *
     * `café` has two spellings that are different strings and the same file on APFS and NTFS. The
     * narrow rule would be "must already be NFC", but there is no normalisation API in the Kotlin
     * standard library and this class is `commonMain`, shared with JS and iOS. Restricting to
     * characters with no decomposed form buys the same guarantee without an `expect`/`actual`.
     */
    @Test
    fun refusesAUsernameWhoseSpellingDependsOnUnicodeNormalisation() {
        val precomposed = "caf\u00E9"
        val decomposed = "cafe\u0301"

        listOf(precomposed, decomposed).forEach { username ->
            assertTrue(
                Issue.UsernameHasIllegalCharacters in validate(username, STRONG_PASSWORD).issues,
                "both spellings of an accented name must be refused, not just the decomposed one",
            )
        }
    }

    /** A username ending in a sibling-directory suffix would claim a path that is not an account. */
    @Test
    fun refusesAUsernameThatNamesASiblingOfAnAccountDirectory() {
        listOf("alice.conflicts", "alice.lock", "alice.unbundle-staging", "ALICE.LOCK").forEach { username ->
            assertTrue(
                Issue.UsernameHasIllegalCharacters in validate(username, STRONG_PASSWORD).issues,
                "\"$username\" names a sibling of an account directory and must be refused",
            )
        }
    }

    /**
     * Windows device names are refused, because they are not filenames on Windows at any path.
     *
     * `con`, `nul`, `aux`, `prn`, `com1`…`com9`, `lpt1`…`lpt9` are made of perfectly ordinary
     * characters, so the character rule cannot see them — an earlier version of its KDoc claimed it
     * could, which was wrong and is exactly the kind of comment a later reader trusts. Matched on the
     * stem: `con.txt` is still `con` there.
     *
     * The desktop app ships an MSI. Without this, signing up as `con` passed validation and then died
     * inside the account bootstrap creating `keystore\con\`, reported as a generic failure after the
     * validator had said the name was fine.
     */
    @Test
    fun refusesAWindowsDeviceName() {
        listOf("con", "NUL", "aux", "prn", "com1", "lpt9", "con.txt", "Nul.b-c").forEach { username ->
            assertTrue(
                Issue.UsernameHasIllegalCharacters in validate(username, STRONG_PASSWORD).issues,
                "\"$username\" is a reserved device name on Windows and must be refused",
            )
        }

        // Windows reserves COM1-COM9 and LPT1-LPT9. Zero is not reserved, and a guard that refused it
        // would be rejecting a legitimate name - the failure mode this rule has already had once.
        listOf("com0", "lpt0").forEach { username ->
            assertFalse(
                Issue.UsernameHasIllegalCharacters in validate(username, STRONG_PASSWORD).issues,
                "\"$username\" is not reserved and must be accepted",
            )
        }
    }

    /**
     * A username long enough to break the paths built from it is refused.
     *
     * The account name is a path component and the longest thing appended to it is
     * `.unbundle-staging`, 17 characters, against a 255-byte component limit. Past that the failures
     * are silent rather than loud: `<user>.lock` stops being creatable and the lock degrades to
     * in-process exclusion — dropping the cross-process guarantee this whole branch exists to add,
     * with only a log line — while `<user>.unbundle-staging` stops being creatable and every inbound
     * push is rejected forever with nothing in the app to explain it.
     */
    @Test
    fun refusesAUsernameTooLongForThePathsBuiltFromIt() {
        val overlong = "a".repeat(ValidateSignUpCredentials.MAX_USERNAME_LENGTH + 1)

        val result = validate(overlong, STRONG_PASSWORD)

        assertTrue(Issue.UsernameTooLong in result.issues, "an overlong username must be refused")
        assertFalse(result.acceptable)
        assertFalse(
            Issue.UsernameTooLong in validate("a".repeat(ValidateSignUpCredentials.MAX_USERNAME_LENGTH), STRONG_PASSWORD).issues,
            "and the cap itself must be allowed",
        )
    }

    /**
     * The control, and the reason the rule is not simply "alphanumeric only".
     *
     * A guard that refuses legitimate input is a worse bug than the one it closes, and these are the
     * ordinary shapes people type. Dots, underscores and hyphens are safe between alphanumerics: none
     * of them can start a relative path, none is a separator, and none is folded away by a filesystem.
     */
    @Test
    fun acceptsOrdinaryUsernames() {
        listOf("alice", "first.last", "a_b", "a-b", "Alice99", "a.b_c-d").forEach { username ->
            val result = validate(username, STRONG_PASSWORD)
            assertFalse(
                Issue.UsernameHasIllegalCharacters in result.issues,
                "\"$username\" is an ordinary username and must be accepted",
            )
        }
    }

    private companion object {
        const val STRONG_PASSWORD = "Tr0ub4dor&3-correct-horse"
    }
}
