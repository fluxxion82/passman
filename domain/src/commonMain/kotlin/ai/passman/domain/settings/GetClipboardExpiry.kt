package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.repository.ClipboardPreferences

class GetClipboardExpiry(
    private val preferences: ClipboardPreferences,
) : Usecase<Unit, ClipboardExpiry> {

    override suspend fun invoke(param: Unit): ClipboardExpiry = preferences.getExpiry()
}
