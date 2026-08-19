package ai.passman.domain.password.model

import kotlinx.serialization.Serializable

/**
 * One user-defined field on a [PasswordEntry]. [secret] fields render concealed with a reveal, the
 * way the password itself does.
 */
@Serializable
data class CustomField(
    val label: String,
    val value: String,
    val secret: Boolean = false,
)
