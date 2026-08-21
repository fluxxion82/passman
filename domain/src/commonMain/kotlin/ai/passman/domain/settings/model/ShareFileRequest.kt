package ai.passman.domain.settings.model

/** What the shared file contains — drives confirmation wording and chooser titles. */
enum class ShareFileKind {
    PublicKeyOnly,
    EntireKeystore,
    PrivateKey,

    /**
     * A version an inbound sync displaced, exported from the recovery screen.
     *
     * Its own kind because the others all assert something this one cannot. A displaced file may be
     * a secret ring, a public ring, or a whole keystore, and nothing in the conflict store says
     * which — so wording that promises "your PRIVATE key ring, encrypted with its passphrase" would
     * be false for half of them, in the direction that matters: telling a user a file is protected
     * when it may not be.
     */
    DisplacedVersion,
}

data class ShareFileRequest(
    val filePath: String,
    val displayName: String,
    val kind: ShareFileKind,
) {
    val fileName: String
        get() = filePath.substringAfterLast('/').substringAfterLast('\\')

    /**
     * One-line description for the platform chooser / save dialog. Lives on the request so the
     * Android chooser and the desktop save dialog can never drift apart on what they claim the
     * file contains.
     */
    val shareTitle: String
        get() = when (kind) {
            ShareFileKind.PublicKeyOnly -> "Sharing public key $displayName (public key only)"
            ShareFileKind.EntireKeystore -> "Sharing keystore file $displayName (entire keystore)"
            ShareFileKind.PrivateKey -> "PRIVATE KEY - $displayName"
            ShareFileKind.DisplacedVersion -> "POSSIBLE PRIVATE KEY - $displayName"
        }
}
