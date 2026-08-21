package ai.passman.domain.user

import ai.passman.domain.user.models.PasswordStrength

/**
 * Gate for new-account credentials. The master password is the sole input to the vault KDF, so the
 * hard rules here are the only thing standing between an offline brute force and a trivial vault.
 */
class ValidateSignUpCredentials {
    enum class Issue {
        UsernameTooShort,
        UsernameTooLong,
        UsernameHasIllegalCharacters,
        PasswordTooShort,
        PasswordContainsUsername,
        PasswordSingleCharacter,
    }

    data class Result(
        val issues: List<Issue>,
        val strength: PasswordStrength,
    ) {
        val acceptable: Boolean get() = issues.isEmpty()
    }

    @OptIn(ExperimentalStdlibApi::class)
    operator fun invoke(username: String, password: String): Result {
        val trimmedUsername = username.trim()
        val issues = buildList {
            if (trimmedUsername.length < MIN_USERNAME_LENGTH) add(Issue.UsernameTooShort)
            if (trimmedUsername.length > MAX_USERNAME_LENGTH) add(Issue.UsernameTooLong)
            if (trimmedUsername.length >= MIN_USERNAME_LENGTH && !isUsableAsAFileName(trimmedUsername)) {
                add(Issue.UsernameHasIllegalCharacters)
            }
            if (password.length < MIN_PASSWORD_LENGTH) add(Issue.PasswordTooShort)
            if (trimmedUsername.length >= MIN_USERNAME_LENGTH &&
                password.contains(trimmedUsername, ignoreCase = true)
            ) {
                add(Issue.PasswordContainsUsername)
            }
            // allEqual has no CharSequence receiver (as of 2.4.20-RC), hence the asSequence bridge.
            if (password.isNotEmpty() && password.asSequence().allEqual()) {
                add(Issue.PasswordSingleCharacter)
            }
        }
        val passwordIssues =
            issues - Issue.UsernameTooShort - Issue.UsernameTooLong - Issue.UsernameHasIllegalCharacters
        val strength = if (passwordIssues.isNotEmpty()) PasswordStrength.Weak else scoreStrength(password)
        return Result(issues, strength)
    }

    /**
     * Whether [username] is safe to build this account's file paths out of.
     *
     * **The username is not a label; it is a path component.** Every artifact this app owns is
     * `keystore/<user>/…` or `pgp/<user>/…`, built by string concatenation, and the sibling
     * directories beside them are `<user>.conflicts`, `<user>.unbundle-staging` and `<user>.lock`.
     * Four rounds of adversarial review each found another way a username that is really a *path*
     * broke something downstream, and they were all the same bug:
     *
     * - `./alice` made the sync exclusion list — which compares basenames — miss `alice.pfx`, so an
     *   inbound bundle replaced the account's RSA identity (`IdentityStoreDisplaceableTest`).
     * - `team/a` nested one account's directory inside another's, putting `team/a`'s lock file inside
     *   the tree `bundle()` walks for `team` and giving the two accounts different locks over one set
     *   of files.
     * - A decomposed spelling of an accented name is a different string but the same file on APFS and
     *   NTFS, so a guard comparing names saw two accounts where the filesystem saw one.
     * - `alice.lock` would claim the path account `alice` uses for its lock file — a file and a
     *   directory at one name.
     *
     * Guarding each consequence separately did not converge. This is the one rule that removes the
     * class: a username must be something a filesystem cannot reinterpret.
     *
     * ## Why ASCII
     *
     * Rejecting a name that is not already NFC would be the narrower rule, but there is no
     * normalisation API in the Kotlin standard library and this class is `commonMain` — shared with
     * JS and iOS — so it cannot reach for `java.text.Normalizer`. Restricting to characters that have
     * no decomposed form gets the same guarantee without an `expect`/`actual` for one predicate.
     * A username here is an account key, not a display name, and nothing shows it to anyone but its
     * owner.
     *
     * ## The shape
     *
     * First and last characters are alphanumeric; `.`, `_` and `-` are allowed between them. That
     * rules out every separator, `.`/`..`, leading dots, and the trailing dots and spaces Windows
     * folds away, along with `<>:"|?*` and control characters — every character Windows reserves.
     *
     * Reserved *device names* are a separate rule, because they are made of perfectly ordinary
     * characters. `con`, `nul`, `aux`, `prn`, `com1`…`com9`, `lpt1`…`lpt9` are not filenames on
     * Windows at any path, with or without an extension — `con.txt` is still `con` — and the desktop
     * app ships an MSI. Without this a user could sign up as `con`, pass validation, and have the
     * account bootstrap die creating `keystore\con\` with a generic failure after the validator
     * said the name was fine. An earlier version of this KDoc claimed the character rule covered
     * these; it does not, and could not.
     *
     * Length is capped for the same reason the character set is: the account name is a path
     * component, and the longest thing appended to it is `.unbundle-staging` (17 characters), against
     * a 255-byte limit on every filesystem this ships to. A name near that limit degrades silently
     * rather than loudly — `<user>.lock` stops being creatable and `ArtifactDirectoryLock` falls back
     * to in-process exclusion with a warning, quietly dropping the cross-process guarantee for that
     * account, while `<user>.unbundle-staging` stops being creatable and every inbound push is
     * rejected forever with nothing in the app to explain it. [MAX_USERNAME_LENGTH] leaves a wide
     * margin under the binding constraint rather than sitting near it.
     *
     * Existing accounts are untouched: this runs only when one is created. An account already named
     * something dangerous keeps working exactly as badly as it did before.
     */
    private fun isUsableAsAFileName(username: String): Boolean {
        if (username.first() !in ALPHANUMERIC || username.last() !in ALPHANUMERIC) return false
        if (username.any { it !in ALPHANUMERIC && it !in INNER_PUNCTUATION }) return false
        // The suffixes that name a sibling of an account directory. A username ending in one would
        // claim a path the app already uses for something that is not an account.
        if (RESERVED_SUFFIXES.any { username.endsWith(it, ignoreCase = true) }) return false
        // Windows device names, matched on the stem: `con.txt` is `con` there, not a file called
        // "con.txt".
        return username.substringBefore('.').lowercase() !in RESERVED_DEVICE_NAMES
    }

    private fun scoreStrength(password: String): PasswordStrength {
        var score = 0
        if (password.length >= MIN_PASSWORD_LENGTH) score++
        if (password.length >= 16) score++
        if (password.length >= 20) score++
        val classes = listOf(
            password.any { it.isLowerCase() },
            password.any { it.isUpperCase() },
            password.any { it.isDigit() },
            password.any { !it.isLetterOrDigit() },
        ).count { it }
        if (classes >= 3) score++
        return when {
            score <= 1 -> PasswordStrength.Weak
            score == 2 -> PasswordStrength.Fair
            score == 3 -> PasswordStrength.Good
            else -> PasswordStrength.Strong
        }
    }

    companion object {
        private val ALPHANUMERIC = ('a'..'z') + ('A'..'Z') + ('0'..'9')

        /** Allowed between the first and last character, never at either end. */
        private val INNER_PUNCTUATION = listOf('.', '_', '-')

        /**
         * Suffixes that name a **sibling** of an account's artifact directory, not an account.
         *
         * Spelled here rather than imported because `domain` is the deepest module and cannot see
         * `DirectoryBundler` or `ArtifactDirectoryLock`, which own the real constants.
         * `UsernameFileSafetyTest` asserts the two sides agree, the same way
         * `DirectoryBundlerSyncExclusionsTest` pins the temp-suffix pair across that boundary.
         */
        private val RESERVED_SUFFIXES = listOf(".conflicts", ".unbundle-staging", ".lock")

        /**
         * Names Windows refuses at any path, extension or not. Lowercase; the check folds case.
         *
         * Not a filesystem concern on Android or macOS, but the account directory this names is
         * created on whichever platform the user signed up on, and the desktop app ships an MSI.
         */
        private val RESERVED_DEVICE_NAMES =
            setOf("con", "prn", "aux", "nul") +
                // 1..9, not 0..9: Windows reserves COM1-COM9 and LPT1-LPT9. COM0 and LPT0 are
                // ordinary names, and refusing them would be the guard rejecting legitimate input.
                (1..9).map { "com$it" } +
                (1..9).map { "lpt$it" }

        const val MIN_USERNAME_LENGTH = 3

        /**
         * Well under the binding constraint rather than at it: the filesystem limit is 255 bytes per
         * name component, the longest suffix appended to a username is `.unbundle-staging` at 17, and
         * an account key has no reason to be long.
         */
        const val MAX_USERNAME_LENGTH = 64
        const val MIN_PASSWORD_LENGTH = 12
    }
}
