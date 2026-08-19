package ai.passman.domain.settings.repository

class DefaultSupportRepository : SupportRepository {
    override val termsOfUse: String = TERMS_OF_USE
    companion object {
        private const val TERMS_OF_USE = "https://callin.com/tos"
    }
}
