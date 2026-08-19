package ai.passman.domain.settings.model

/** What the shared file contains — drives confirmation wording and chooser titles. */
enum class ShareFileKind {
    PublicKeyOnly,
    EntireKeystore,
    PrivateKey,
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
        }
}
