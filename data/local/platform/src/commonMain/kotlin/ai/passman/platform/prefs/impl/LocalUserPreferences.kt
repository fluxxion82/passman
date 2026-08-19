package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.KdfParams
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import com.russhwolf.settings.Settings
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

class LocalUserPreferences(
    encryptedFactory: EncryptionSettingsFactory,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : UserPreferences {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)
    private val format = Json { allowStructuredMapKeys = true; ignoreUnknownKeys = true }
    private var sessionId: String? = null

    init {
        // The single-slot sync address is gone; the chooser reads TrustedDevice.lastHost.
        settings.remove("last_transfer_address")
    }

    /**
     * Serialises every credential write, so [replaceCredential]'s compare and write cannot be split
     * by a concurrent [upsert] in this process. Cross-process the guarantee is advisory only —
     * `Settings` has no compare-and-set to build on.
     */
    private val credentialLock = Mutex()

    override suspend fun getUser(): AppUser = withContext(coroutinesContextFacade.io) {
        val userName = settings.getStringOrNull(USER_NAME) ?: return@withContext AppUser.Anonymous
        val hash = settings.getStringOrNull(HASH) ?: return@withContext AppUser.Anonymous
        val salt = settings.getStringOrNull(SALT) ?: return@withContext AppUser.Anonymous
        val kdf = settings.getStringOrNull(KDF)?.let { runCatching { format.decodeFromString<KdfParams>(it) }.getOrNull() }
        AppUser.LoggedIn(userName = userName, password = Password(hash = hash, salt = salt, kdf = kdf))
    }

    override suspend fun upsert(user: AppUser) = withContext(coroutinesContextFacade.io) {
        val (name, password) = when (user) {
            is AppUser.LoggedIn -> user.userName to user.password
            is AppUser.AccountCreated -> user.userName to user.password
            else -> return@withContext
        }
        credentialLock.withLock { writeCredential(name, password) }
    }

    override suspend fun replaceCredential(
        username: String,
        expected: Password,
        replacement: Password,
    ): Boolean = withContext(coroutinesContextFacade.io) {
        // Compare and write under one lock: the interface default's read-then-upsert lets two
        // concurrent changes both pass the compare, and the loser then restores a credential the
        // winner just replaced — the exact strand this primitive exists to prevent.
        credentialLock.withLock {
            if (loadStoredMap()[username] != expected) return@withContext false
            writeCredential(username, replacement)
            true
        }
    }

    private fun writeCredential(name: String, password: Password) {
        settings.putString(USER_NAME, name)
        settings.putString(HASH, password.hash)
        settings.putString(SALT, password.salt)
        if (password.kdf != null) settings.putString(KDF, format.encodeToString(password.kdf)) else settings.remove(KDF)

        // Write the full Password (incl. KDF params) under the v2 key; migrate any legacy pair-map.
        val existing = loadStoredMap().toMutableMap()
        existing[name] = password
        settings.putString(STORED_CREDS_V2, format.encodeToString(existing))
    }

    override suspend fun getStoredCredentials(username: String): Password? = withContext(coroutinesContextFacade.io) {
        loadStoredMap()[username]
    }

    override suspend fun getKnownUsernames(): List<String> = withContext(coroutinesContextFacade.io) {
        val names = loadStoredMap().keys
        val lastUsed = settings.getStringOrNull(USER_NAME)
        val remaining = names
            .filter { it != lastUsed }
            .sortedBy { it.lowercase() }
        lastUsed?.takeIf { it in names }?.let { listOf(it) + remaining } ?: remaining
    }

    /** Reads the v2 credential map, falling back to the legacy pair-map (kdf = null = legacy PBKDF2). */
    private fun loadStoredMap(): Map<String, Password> {
        settings.getStringOrNull(STORED_CREDS_V2)?.let { raw ->
            runCatching { format.decodeFromString<Map<String, Password>>(raw) }
                .onFailure {
                    // A present-but-unparseable v2 map is corruption or tampering — falling back to
                    // the legacy PBKDF2 pair-map silently would be a KDF downgrade, so make it loud.
                    KLogger.e(it) { "stored v2 credential map unreadable; falling back to legacy map" }
                }
                .getOrNull()?.let { return it }
        }
        val legacy = settings.getStringOrNull(STORED_CREDS) ?: return emptyMap()
        val pairMap = runCatching {
            format.decodeFromString<Map<String, Pair<String, String>?>>(legacy)
        }.getOrNull() ?: return emptyMap()
        return pairMap.mapNotNull { (name, pair) ->
            pair?.let { (hash, salt) -> name to Password(hash, salt, kdf = null) }
        }.toMap()
    }

    override suspend fun getUserState(): UserState? = withContext(coroutinesContextFacade.io) {
        val state = settings.getStringOrNull(USER_STATE_KEY)
        KLogger.d { "getUserState: $state" }
        when (state) {
            LOGGED_IN -> UserState.LoggedIn
            null -> null
            else -> UserState.Anonymous
        }
    }

    override suspend fun setUserState(state: UserState) = withContext(coroutinesContextFacade.io) {
        KLogger.d { "setUserState: $state" }
        when (state) {
            is UserState.LoggedIn -> settings.putString(USER_STATE_KEY, LOGGED_IN)
            else -> settings.remove(USER_STATE_KEY)
        }
    }

    @OptIn(ExperimentalUuidApi::class)
    override suspend fun getSessionId(): String =
        sessionId ?: Uuid.random().toString().also { sessionId = it }

    override suspend fun clear() {
        sessionId = null
    }

    private companion object {
        const val PREFS_NAME = "user_info"
        const val USER_NAME = "user_name"
        const val HASH = "hash"
        const val SALT = "salt"
        const val KDF = "kdf"
        const val STORED_CREDS = "stored"
        const val STORED_CREDS_V2 = "stored_v2"
        const val USER_STATE_KEY = "loggedInFlag"
        const val LOGGED_IN = "logged_in"
    }
}
