package ai.passman.platform.prefs

import com.russhwolf.settings.PreferencesSettings
import java.security.Key
import java.util.prefs.AbstractPreferences
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `java.util.prefs` caps every value at 8192 chars (`AbstractPreferences.MAX_VALUE_LENGTH`), and
 * the trusted-device store writes its whole device list as one encrypted value. Two post-quantum
 * pairings (~4.7KB of JSON each, inflated ~4/3 by AES-GCM + base64) blow past the cap, the write
 * throws `IllegalArgumentException("Value too long")`, and pairing the second device fails.
 *
 * [EncryptedPreferences] therefore splits oversized encrypted payloads across `<key>#0..#n-1`
 * entries with a `chunks:<n>` marker under the main key. These tests pin that behavior against an
 * in-memory [AbstractPreferences], which enforces the same 8192-char cap as the production node.
 */
class EncryptedPreferencesChunkingTest {

    /** Map-backed delegate; `AbstractPreferences.put` enforces MAX_VALUE_LENGTH exactly like prod. */
    private class MemoryPreferences : AbstractPreferences(null, "") {
        val values = linkedMapOf<String, String>()
        override fun putSpi(key: String, value: String) { values[key] = value }
        override fun getSpi(key: String): String? = values[key]
        override fun removeSpi(key: String) { values.remove(key) }
        override fun removeNodeSpi() { values.clear() }
        override fun keysSpi(): Array<String> = values.keys.toTypedArray()
        override fun childrenNamesSpi(): Array<String> = emptyArray()
        override fun childSpi(name: String): AbstractPreferences = throw UnsupportedOperationException()
        override fun syncSpi() = Unit
        override fun flushSpi() = Unit
    }

    private val key: Key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
    private val delegate = MemoryPreferences()
    private val prefs = EncryptedPreferences(key, delegate)

    /** Deterministic non-repeating payload so a chunk mixup cannot accidentally reassemble. */
    private fun payload(length: Int): String = buildString(length) {
        var i = 0
        while (this.length < length) {
            append("segment-").append(i).append(';')
            i++
        }
    }.take(length)

    @Test
    fun `a value larger than the prefs cap round-trips via chunking`() {
        val big = payload(20_000)
        prefs.put("devices", big)
        assertEquals(big, prefs.get("devices", null))
    }

    @Test
    fun `every stored entry stays under the prefs value cap`() {
        prefs.put("devices", payload(20_000))
        delegate.values.forEach { (k, v) ->
            assertTrue(v.length <= 8192, "entry $k is ${v.length} chars, over the java.util.prefs cap")
        }
    }

    @Test
    fun `small values stay single-entry for backward compatibility`() {
        prefs.put("devices", payload(100))
        assertEquals(1, delegate.values.size)
        assertEquals(payload(100), prefs.get("devices", null))
    }

    @Test
    fun `shrinking a chunked value removes the stale chunk entries`() {
        prefs.put("devices", payload(20_000))
        assertTrue(delegate.values.size > 1, "precondition: big value should have chunked")
        prefs.put("devices", payload(100))
        assertEquals(1, delegate.values.size)
        assertEquals(payload(100), prefs.get("devices", null))
    }

    @Test
    fun `shrinking to fewer chunks leaves no orphan tail`() {
        prefs.put("devices", payload(40_000))
        val bigCount = delegate.values.size
        prefs.put("devices", payload(9_000))
        assertTrue(delegate.values.size < bigCount, "smaller value should use fewer entries")
        assertEquals(payload(9_000), prefs.get("devices", null))
    }

    @Test
    fun `remove drops the marker and every chunk`() {
        prefs.put("devices", payload(20_000))
        prefs.remove("devices")
        assertEquals(0, delegate.values.size)
        assertEquals(null, prefs.get("devices", null))
    }

    @Test
    fun `chunked and unchunked keys coexist`() {
        prefs.put("devices", payload(20_000))
        prefs.put("marker", "1")
        assertEquals(payload(20_000), prefs.get("devices", null))
        assertEquals("1", prefs.get("marker", null))
    }

    @Test
    fun `settings facade round-trips a two-PQ-device-sized list`() {
        // ~12.6K encrypted chars is the real-world failure: two paired devices with ML-DSA-65
        // and X25519+ML-KEM-768 public keys in one JSON list.
        val settings = PreferencesSettings(prefs)
        val deviceListJson = payload(9_400)
        settings.putString("devices", deviceListJson)
        assertEquals(deviceListJson, settings.getStringOrNull("devices"))
    }
}
