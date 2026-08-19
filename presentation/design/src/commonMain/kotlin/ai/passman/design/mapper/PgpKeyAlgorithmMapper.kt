package ai.passman.design.mapper

import ai.passman.domain.pgp.model.PgpKeyAlgorithm

fun PgpKeyAlgorithm.toItemListName(): String {
    return when (this) {
        PgpKeyAlgorithm.DSA_SIGN -> "DSA (sign only)"
        PgpKeyAlgorithm.RSA_SIGN -> "RSA (sign only)"
        PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> "Elgamal (encrypt only)"
        PgpKeyAlgorithm.RSA_ENCRYPT -> "RSA (encrypt only)"
        PgpKeyAlgorithm.ED25519 -> "Ed25519"
    }
}

fun PgpKeyAlgorithm.toPrimaryKeyName(): String {
    return when (this) {
        PgpKeyAlgorithm.DSA_SIGN -> "DSA (sign only)"
        PgpKeyAlgorithm.RSA_SIGN -> "RSA (sign only)"
        PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> "DSA and Elgamal"
        PgpKeyAlgorithm.RSA_ENCRYPT -> "RSA and RSA"
        PgpKeyAlgorithm.ED25519 -> "Ed25519 and Curve25519"
    }
}
