package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.repository.ClipboardPreferences

class SetClipboardExpiry(
    private val preferences: ClipboardPreferences,
) : Usecase<ClipboardExpiry, Unit> {

    override suspend fun invoke(param: ClipboardExpiry) = preferences.setExpiry(param)
}
