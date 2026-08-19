package ai.passman.repo.datamapper

import ai.passman.pgp.utils.isRevoked
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.model.UserId
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature

fun PGPPublicKey.toPgpKey(path: String, fileName: String, subKeys: List<PgpKey>): PgpKey {
    val isRevoked = signatures.asSequence().any { it.isRevoked() }
    val expirationTime = if (validSeconds > 0) creationTime.time + validSeconds * 1000 else null

    return PgpKey(
        fileName = fileName,
        path = path,
        type = PgpKeyType.Public,
        keyId = keyID,
        creationTime = creationTime.time,
        expirationTime = expirationTime,
        isRevoked = isRevoked,
        algorithm = algorithm.toAlgorithm(),
        bitStrength = bitStrength,
        userIds = userIDs.asSequence().map { UserId.processUserId(it, isIdRevoked(userIDs, it)) }.toList(),
        fingerprint = fingerprint.joinToString("") { byte -> String.format("%02X", byte) },
        isMaster = isMasterKey,
        isEncryptionKey = isEncryptionKey,
        isSigningKey = false,
        subKeys = subKeys
    )
}

fun PGPPublicKey.isIdRevoked(userIds: Iterator<String>, userIdToCheck: String): Boolean {
    while (userIds.hasNext()) {
        val userId = userIds.next()
        if (userId == userIdToCheck) {
            val signatures = getSignaturesForID(userId)
            while (signatures.hasNext()) {
                val signature = signatures.next() as PGPSignature
                if (signature.signatureType == PGPSignature.CERTIFICATION_REVOCATION) {
                    return true
                }
            }
            return false
        }
    }

    return false
}
