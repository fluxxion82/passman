package ai.passman.domain.initialization.models

data class AppInformation(
    val version: Version,
    val versionCode: Int,
    val id: String,
    val environment: Environment,
    val debug: Boolean,
    val userHomeDir: String,
)

data class Version(
    val name: String,
    val build: String,
    val additionalInfo: String
)

enum class Environment {
    SANDBOX,
    LOCAL,
    STAGING,
    PROD
}
