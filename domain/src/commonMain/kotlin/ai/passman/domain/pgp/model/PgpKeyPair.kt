package ai.passman.domain.pgp.model

data class PgpKeyPair(
    val publicKey: PgpKey,
    val secretKey: PgpKey?,
)
