package ai.passman.pgp.utils

import org.bouncycastle.openpgp.PGPSignature

fun PGPSignature.isRevoked(): Boolean {
    return signatureType == PGPSignature.KEY_REVOCATION || signatureType == PGPSignature.SUBKEY_REVOCATION
}
