package ai.passman.domain.pgp.model

enum class PgpKeyAlgorithm {
    DSA_SIGN, // sign only // todo
    RSA_SIGN, // sign only
    ELGAMAL_ENCRYPT, // encrypt only
    RSA_ENCRYPT, // encrypt only
    ED25519,
    ;
}
