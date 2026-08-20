package ai.passman.design.mapper

import ai.passman.domain.pgp.model.PgpKeyAlgorithm

fun PgpKeyAlgorithm.toItemListName(): String {
    return when (this) {
        PgpKeyAlgorithm.DSA_SIGN -> "DSA (sign only)"
        PgpKeyAlgorithm.RSA_SIGN -> "RSA (sign only)"
        PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> "Elgamal (encrypt only)"
        PgpKeyAlgorithm.RSA_ENCRYPT -> "RSA (encrypt only)"
        PgpKeyAlgorithm.ED25519 -> "Ed25519 (legacy)"
        PgpKeyAlgorithm.ECDSA_ECDH -> "NIST ECDSA"
        PgpKeyAlgorithm.ED25519_X25519 -> "Ed25519"
        PgpKeyAlgorithm.ED448_X448 -> "Ed448"
    }
}

fun PgpKeyAlgorithm.toPrimaryKeyName(): String {
    return when (this) {
        PgpKeyAlgorithm.DSA_SIGN -> "DSA (sign only)"
        PgpKeyAlgorithm.RSA_SIGN -> "RSA (sign only)"
        PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> "DSA and Elgamal"
        PgpKeyAlgorithm.RSA_ENCRYPT -> "RSA and RSA"
        PgpKeyAlgorithm.ED25519 -> "Ed25519 and Curve25519 (legacy codepoints)"
        PgpKeyAlgorithm.ECDSA_ECDH -> "ECDSA and ECDH"
        PgpKeyAlgorithm.ED25519_X25519 -> "Ed25519 and X25519"
        PgpKeyAlgorithm.ED448_X448 -> "Ed448 and X448"
    }
}
