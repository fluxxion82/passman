package ai.passman.domain.user

import ai.passman.domain.user.models.PasswordStrength

/**
 * Gate for new-account credentials. The master password is the sole input to the vault KDF, so the
 * hard rules here are the only thing standing between an offline brute force and a trivial vault.
 */
class ValidateSignUpCredentials {
    enum class Issue {
        UsernameTooShort,
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
        val passwordIssues = issues - Issue.UsernameTooShort - Issue.UsernameHasIllegalCharacters
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
     * folds away — and, because it excludes `<>:"|?*` and control characters along with everything
     * else not listed, the Windows-reserved set as well.
     *
     * Existing accounts are untouched: this runs only when one is created. An account already named
     * something dangerous keeps working exactly as badly as it did before.
     */
    private fun isUsableAsAFileName(username: String): Boolean {
        if (username.first() !in ALPHANUMERIC || username.last() !in ALPHANUMERIC) return false
        if (username.any { it !in ALPHANUMERIC && it !in INNER_PUNCTUATION }) return false
        // The suffixes that name a sibling of an account directory. A username ending in one would
        // claim a path the app already uses for something that is not an account.
        return RESERVED_SUFFIXES.none { username.endsWith(it, ignoreCase = true) }
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

        const val MIN_USERNAME_LENGTH = 3
        const val MIN_PASSWORD_LENGTH = 12
    }
}
