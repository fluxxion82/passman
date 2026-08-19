package ai.passman.crypto.vault

/**
 * The session-scoped owner of the unwrapped [VaultSessionKey].
 *
 * The key itself is created by a login and has to outlive that call — every later vault read, vault
 * write and key-file unwrap needs it — but it must not outlive the *session*. Koin's session scope
 * already has exactly that lifetime, so this holder is registered as a scoped instance there and its
 * `onClose` callback calls [destroy]. Closing the scope (logout, or a rolled-back signup) therefore
 * zeroes the key material without any caller having to remember to.
 *
 * A holder rather than the key itself, for two reasons. Koin has no way to *put* an already-created
 * instance into a scope with an `onClose` callback attached — only a definition can carry one — and a
 * definition cannot produce the key, because producing it needs the login password, which exists only
 * inside the login call. The holder is the definition; the login binds into it.
 *
 * This type is `commonMain` for the same reason [VaultSessionKey] is: `LocalUserRepository` is a
 * `commonMain` file in a module that compiles for iOS.
 *
 * **Not thread-safe on purpose.** Binding happens once per login, on the login coroutine, before any
 * consumer can reach the scope; adding a lock here would suggest a concurrent-rebind case that does
 * not exist and would hide it if one appeared.
 */
class VaultSession {

    private var sessionKey: VaultSessionKey? = null

    /** The bound key, or null when no one has signed in on this scope yet. */
    val current: VaultSessionKey?
        get() = sessionKey

    /**
     * Take ownership of [sessionKey].
     *
     * Any previously bound key is destroyed first: a second login on a live scope replaces the
     * session, and leaving the old key material alive would defeat the point of scoping it. Binding
     * the *same* key twice is a no-op rather than a self-destruct.
     */
    fun bind(sessionKey: VaultSessionKey) {
        if (this.sessionKey === sessionKey) return
        this.sessionKey?.destroy()
        this.sessionKey = sessionKey
    }

    /** The bound key, or a loud failure. Callers that need a session must not silently degrade. */
    fun require(): VaultSessionKey =
        sessionKey ?: throw IllegalStateException("no vault session is bound; sign in first")

    /** Zero and release the key. Idempotent — the scope may be closed more than once. */
    fun destroy() {
        sessionKey?.destroy()
        sessionKey = null
    }

    /** Redacted for the same reason [VaultSessionKey.toString] is: this object transitively holds a key. */
    override fun toString(): String = "VaultSession(**redacted**)"
}
