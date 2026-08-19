package ai.passman.domain.pgp.model

import kotlinx.serialization.Serializable

@Serializable
data class UserId(
    val name: String,
    val email: String,
    val comment: String = "",
    val isRevoked: Boolean,
) {
    override fun toString(): String {
        val namePart = name
        val emailPart = if (email.isNotEmpty()) " <${email}>" else ""
        val commentPart = if (comment.isNotEmpty()) " (${comment})" else ""
        return "$namePart$emailPart$commentPart"
    }

    companion object {
        fun processUserId(userId: String, isRevoked: Boolean): UserId {
            val nameEmailComment = Regex("""(.*) <(.*)> \((.*)\)""")
            val nameEmail = Regex("""(.*) <(.*)>""")
            val allMatchResult = nameEmailComment.matchEntire(userId)
            val nameEmailMatchResult = nameEmail.matchEntire(userId)

            return if (allMatchResult != null) {
                val (name, email, comment) = allMatchResult.destructured
                UserId(name = name, email = email, isRevoked = isRevoked)
            } else if(nameEmailMatchResult != null) {
                val (name, email) = nameEmailMatchResult.destructured
                UserId(name = name, email = email, isRevoked = isRevoked)
            } else {
                UserId(name = userId, email = "", isRevoked = isRevoked)
            }
        }
    }
}

