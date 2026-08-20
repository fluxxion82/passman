package ai.passman.platform.prefs.impl

import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.platform.prefs.BiometricUnlockStore
import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.service.WrappedSecret
import com.russhwolf.settings.Settings
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The wrapped master password, in the same encrypted store every other preference uses.
 *
 * The encryption around the store is not what protects this value — the hardware key is — but it is
 * free and it keeps the blob out of a plain-text backup, so there is no reason to sidestep it.
 *
 * Ciphertext and IV go in as **one** JSON value rather than two keys. Two keys can be half-written
 * (a kill during enrolment, a store that flushes lazily) and the result is an enrolment that fails
 * at the next unlock with no way to tell it apart from a genuinely invalidated key. One value is
 * either there or it is not.
 */
@OptIn(ExperimentalEncodingApi::class)
class LocalBiometricUnlockPreferences(
    encryptedFactory: EncryptionSettingsFactory,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : BiometricUnlockStore {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)
    private val format = Json { ignoreUnknownKeys = true }

    override suspend fun read(username: String): WrappedSecret? = withContext(coroutinesContextFacade.io) {
        val raw = settings.getStringOrNull(key(username)) ?: return@withContext null
        runCatching {
            val stored = format.decodeFromString<StoredWrappedSecret>(raw)
            WrappedSecret(
                ciphertext = Base64.decode(stored.ciphertext),
                iv = Base64.decode(stored.iv),
            )
        }.getOrElse {
            // Unreadable means unopenable. Drop it rather than leaving a record that makes the
            // login screen offer a button which can only ever fail.
            KLogger.e(it) { "biometric unlock: stored enrolment is unreadable — discarding it" }
            settings.remove(key(username))
            null
        }
    }

    override suspend fun write(username: String, wrapped: WrappedSecret) = withContext(coroutinesContextFacade.io) {
        val stored = StoredWrappedSecret(
            ciphertext = Base64.encode(wrapped.ciphertext),
            iv = Base64.encode(wrapped.iv),
        )
        settings.putString(key(username), format.encodeToString(stored))
    }

    override suspend fun remove(username: String) = withContext(coroutinesContextFacade.io) {
        settings.remove(key(username))
    }

    @Serializable
    private data class StoredWrappedSecret(val ciphertext: String, val iv: String)

    private fun key(username: String) = "$WRAPPED_SECRET_PREFIX$username"

    private companion object {
        const val PREFS_NAME = "biometric_unlock"
        const val WRAPPED_SECRET_PREFIX = "wrapped_"
    }
}
