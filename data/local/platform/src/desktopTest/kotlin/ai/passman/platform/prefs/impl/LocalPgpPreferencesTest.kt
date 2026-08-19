package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyType
import com.russhwolf.settings.MapSettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class LocalPgpPreferencesTest {

    @Test
    fun `entries stored before the package rename still decode`() = runBlocking {
        val settings = MapSettings().apply {
            putString(
                "pgp_keys",
                """[{"fileName":"alice.asc","path":"/keys/alice.asc",""" +
                    """"type":{"type":"ai.sterling.passman.domain.pgp.model.PgpKeyType.Secret"},""" +
                    """"keyId":42,"creationTime":1,"expirationTime":null,"isRevoked":false,""" +
                    """"algorithm":"RSA_GENERAL","bitStrength":4096,"userIds":[],""" +
                    """"fingerprint":"AB12","isMaster":true,"isSigningKey":true,""" +
                    """"isEncryptionKey":false}]""",
            )
        }

        val list = preferences(settings).getPgpKeyList()

        assertEquals(1, list.size)
        assertEquals(PgpKeyType.Secret, list.single().type)
        assertEquals("alice.asc", list.single().fileName)
    }

    @Test
    fun `writes use the pinned short discriminators`() = runBlocking {
        val settings = MapSettings()

        preferences(settings).addPgpKey(key(type = PgpKeyType.Public))

        val stored = settings.getStringOrNull("pgp_keys").orEmpty()
        assertTrue("\"public\"" in stored, "expected pinned discriminator in: $stored")
        assertFalse("ai.passman" in stored, "package name must not leak into stored JSON: $stored")
    }

    @Test
    fun `added keys round trip`() = runBlocking {
        val preferences = preferences(MapSettings())

        preferences.addPgpKey(key(type = PgpKeyType.Secret))

        assertEquals(listOf(PgpKeyType.Secret), preferences.getPgpKeyList().map { it.type })
    }

    @Test
    fun `developer key imported flag defaults to false and is keyed per account`() = runBlocking {
        val preferences = preferences(MapSettings())

        assertFalse(preferences.isDeveloperKeyImported("alice"))

        preferences.setDeveloperKeyImported("alice")

        assertTrue(preferences.isDeveloperKeyImported("alice"))
        assertFalse(preferences.isDeveloperKeyImported("bob"), "the flag is per-account")
    }

    @Test
    fun `developer key imported flag does not disturb the stored key list`() = runBlocking {
        val settings = MapSettings()
        val preferences = preferences(settings)
        preferences.addPgpKey(key(type = PgpKeyType.Public))

        preferences.setDeveloperKeyImported("alice")

        assertEquals(listOf(PgpKeyType.Public), preferences.getPgpKeyList().map { it.type })
    }

    private fun key(type: PgpKeyType) = PgpKey(
        fileName = "bob.asc",
        path = "/keys/bob.asc",
        type = type,
        keyId = 7,
        creationTime = 2,
        expirationTime = null,
        isRevoked = false,
        algorithm = "RSA_GENERAL",
        bitStrength = 4096,
        userIds = emptyList(),
        fingerprint = "CD34",
        isMaster = false,
        isSigningKey = false,
        isEncryptionKey = true,
    )

    private fun preferences(settings: MapSettings) = LocalPgpPreferences(
        encryptedFactory = object : EncryptionSettingsFactory {
            override fun createEncrypted(name: String) = settings
        },
    )
}
