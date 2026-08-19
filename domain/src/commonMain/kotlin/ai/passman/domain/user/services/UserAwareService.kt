package ai.passman.domain.user.services

import ai.passman.domain.user.models.AppUser

interface UserAwareService {
    suspend fun onUserChanged(user: AppUser)
}
