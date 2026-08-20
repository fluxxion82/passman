package ai.passman.domain.pgp.model

/**
 * The key shapes a user can choose when creating a PGP key. A UI choice, not a wire format — the
 * algorithm that ends up on a stored key is [PgpKey.algorithm], a String, deliberately.
 *
 * A key made with one of the elliptic-curve options is unreadable to a peer running a build that
 * predates it. That is the same "both devices need the same build" caveat that already applies to
 * an entry's TOTP seed and custom fields, and it is written down in the README's sync section.
 */
enum class PgpKeyAlgorithm {
    DSA_SIGN, // sign only // todo
    RSA_SIGN, // sign only
    ELGAMAL_ENCRYPT, // encrypt only
    RSA_ENCRYPT, // encrypt only

    /** Ed25519 + Curve25519 under the pre-RFC-9580 codepoints. The oldest EC option here, and the most widely readable. */
    ED25519,

    /** NIST ECDSA + ECDH. Curve follows the chosen length: 256 -> P-256, 384 -> P-384, 521 -> P-521. */
    ECDSA_ECDH,

    /** Ed25519 + X25519 under their own RFC 9580 codepoints. */
    ED25519_X25519,

    /** Ed448 + X448. Highest margin on offer, and the least widely supported. */
    ED448_X448,
    ;
}
