package ai.passman.platform.service

/**
 * The slice of the system clipboard the expiry needs: put text on it, and take it back off.
 *
 * There is deliberately **no read**. The expiry used to decide whether to clear by reading the
 * clipboard back and comparing it against a kept copy of the secret, and that was wrong twice
 * over. On Android 12+ reading a clip another app wrote raises the system's "Passman pasted from
 * your clipboard" notification — precisely in the case where Passman is *not* going to touch
 * anything. And a comparison cannot tell "the clip we wrote" from "an identical clip somebody else
 * wrote since", so an address, a URL or a one-time code that happened to match would be erased as
 * though it were ours.
 *
 * What replaces it is ownership: [write] hands back a [ClipToken] for that one write, and the token
 * answers whether the clipboard still holds *that* clip. Every platform can answer that without
 * looking at the content — AWT reports ownership loss, Android reports clip changes and describes
 * the current clip without counting as a read.
 *
 * Kept this small on purpose — [ExpiringClipboard] holds all of the timing and cancellation logic,
 * so each platform implementation is only the handful of lines that talk to its own clipboard API.
 */
interface SystemClipboard {
    /**
     * Puts [text] on the clipboard and returns a token standing for that write. Each call returns a
     * fresh token; an earlier one may report itself as no longer ours from this moment on.
     */
    fun write(text: String): ClipToken

    fun clear()
}

/**
 * One write's claim on the clipboard.
 *
 * The single question worth asking of it is [stillOurs], and the answer is only ever used to
 * *withhold* a clear. Wiping a clipboard we do not own destroys something the user cannot get back;
 * a password lingering a while longer does not. So anything short of proof — ownership already
 * lost, the OS declining to say, a platform that cannot tell — must answer `false`.
 */
interface ClipToken {
    /**
     * True only while the clipboard can be shown to still hold the clip this token came from,
     * *without reading its contents*. Unknown answers false.
     */
    fun stillOurs(): Boolean
}
