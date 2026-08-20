package ai.passman.repo.datamapper

fun Int.toAlgorithm(): String {
    return when (this) {
        1 -> "RSA"
        2 -> "RSA ENCRYPT"
        3 -> "RSA SIGN"
        16 -> "ELGAMAL ENCRYPT"
        17 -> "DSA"
        18 -> "ECDH (Curve25519)"
        19 -> "ECDSA"
        20 -> "ELGAMAL"
        21 -> "DIFFIE HELLMAN"
        22 -> "Ed25519 (legacy EdDSA)"
        25 -> "X25519"
        26 -> "X448"
        27 -> "Ed25519"
        28 -> "Ed448"
        in 100..110 -> "EXPERIMENTAL ($this)"
        // Keep the id. A key from a newer implementation renders here, and "Unknown" alone leaves
        // the user with nothing to search for; "Unknown (35)" is an answer.
        else -> "Unknown ($this)"
    }
}

fun String.toAlgorithm(): Int {
    return when (this) {
        "RSA" -> 1
        "RSA ENCRYPT" -> 2
        "RSA SIGN" -> 3
        "ELGAMAL ENCRYPT" -> 16
        "DSA" -> 17
        "EC", "ECDH (Curve25519)" -> 18
        "ECDSA" -> 19
        "ELGAMAL" -> 20
        "DIFFIE HELLMAN" -> 21
        "EDDSA", "Ed25519 (legacy EdDSA)" -> 22
        "X25519" -> 25
        "X448" -> 26
        "Ed25519" -> 27
        "Ed448" -> 28
        else -> 100
    }
}
