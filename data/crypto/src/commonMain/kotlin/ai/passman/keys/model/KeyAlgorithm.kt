package ai.passman.keys.model

sealed interface PGPKeyAlgo
sealed interface KeyAlgo

data object RSA: PGPKeyAlgo, KeyAlgo

//object AES : Key
data object DSA : PGPKeyAlgo
data object ELGAMAL : PGPKeyAlgo
data object ECDSA : PGPKeyAlgo
data object ECDH : PGPKeyAlgo
data object EDDSA : PGPKeyAlgo
