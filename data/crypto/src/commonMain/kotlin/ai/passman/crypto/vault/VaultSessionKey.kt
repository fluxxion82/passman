package ai.passman.crypto.vault

/**
 * The unwrapped Device Master Key, held for the lifetime of one login session and nothing longer.
 *
 * This lives in `commonMain` on purpose. `LocalPasswordRepository` and `LocalUserRepository` are
 * `commonMain` files in a module that compiles `iosArm64`/`iosSimulatorArm64`, so the moment a JVM
 * type appears in their declarations the iOS targets stop building. Only the *implementation* of
 * [VaultCipher] is JVM/Android; this holder and the interface are not.
 *
 * The material is deliberately opaque. There is no public accessor returning the array, no
 * `equals`/`hashCode` (identity comparison is the right one for a key handle, and a content compare
 * invites a non-constant-time one), and [toString] is redacted so that a stray log line, a crash
 * report or a debugger's default rendering of an enclosing object cannot print the key. It must never
 * be logged, serialized, placed in `AppUser`, or written to preferences.
 *
 * Wiping is best-effort in the same sense `HybridKem.wipe` documents: [destroy] zeroes the array this
 * object holds — which is the caller's array, not a copy — but any bytes the JCE has already copied
 * into its own buffers are outside this object's control.
 */
class VaultSessionKey internal constructor(private val material: ByteArray) {

    init {
        require(material.size == MATERIAL_BYTES) {
            "vault session key must be $MATERIAL_BYTES bytes, was ${material.size}"
        }
    }

    private var destroyed = false

    /**
     * Internal so the raw key never escapes this module.
     *
     * Throws once [destroy] has run rather than handing back an array of zeros: a destroyed key that
     * silently degraded to 32 zero bytes would produce a vault that looks perfectly well-formed and
     * that anyone can open, and nothing downstream would notice.
     */
    internal fun material(): ByteArray {
        check(!destroyed) { "vault session key has been destroyed" }
        return material
    }

    /** Zero the key material. Idempotent; every later use fails loudly. */
    fun destroy() {
        material.fill(0)
        destroyed = true
    }

    override fun toString(): String = "VaultSessionKey(**redacted**)"

    internal companion object {
        /** 256 bits, matching the Device Master Key the keyring wraps. */
        const val MATERIAL_BYTES = 32
    }
}
