package ai.passman.domain.settings.service

interface WebBrowserService {
    suspend fun openLink(url: String)
}
