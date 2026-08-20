package ai.passman.domain.user

import ai.passman.domain.user.models.PasswordStrength

/**
 * Gate for new-account credentials. The master password is the sole input to the vault KDF, so the
 * hard rules here are the only thing standing between an offline brute force and a trivial vault.
 */
class ValidateSignUpCredentials {
    enum class Issue {
        UsernameTooShort,
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
        val passwordIssues = issues - Issue.UsernameTooShort
        val strength = if (passwordIssues.isNotEmpty()) PasswordStrength.Weak else scoreStrength(password)
        return Result(issues, strength)
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
        const val MIN_USERNAME_LENGTH = 3
        const val MIN_PASSWORD_LENGTH = 12
    }
}
