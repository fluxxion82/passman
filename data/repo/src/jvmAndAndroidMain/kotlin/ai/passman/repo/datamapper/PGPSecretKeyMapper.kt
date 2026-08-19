package ai.passman.repo.datamapper

import ai.passman.pgp.utils.isRevoked
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.model.UserId
import org.bouncycastle.openpgp.PGPSecretKey

fun PGPSecretKey.toPgpKey(path: String, fileName: String, subKeys: List<PgpKey>): PgpKey {
    val publicKey = publicKey
    val isRevoked = publicKey.signatures.asSequence().any { it.isRevoked() }
    val expirationTime = if (publicKey.validSeconds > 0) publicKey.creationTime.time + publicKey.validSeconds * 1000 else null

    return PgpKey(
        fileName = fileName,
        path = path,
        type = PgpKeyType.Secret,
        keyId = keyID,
        creationTime = publicKey.creationTime.time,
        expirationTime = expirationTime,
        isRevoked = isRevoked,
        algorithm = publicKey.algorithm.toAlgorithm(),
        bitStrength = publicKey.bitStrength,
        userIds = userIDs.asSequence().map { UserId.processUserId(it, publicKey.isIdRevoked(userIDs, it)) }.toList(),
        fingerprint = publicKey.fingerprint.joinToString("") { byte -> String.format("%02X", byte) },
        isMaster = publicKey.isMasterKey,
        isEncryptionKey = false,
        isSigningKey = isSigningKey,
        isEncrypted = !isPrivateKeyEmpty,
        subKeys = subKeys
    )
}
