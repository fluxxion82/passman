package ai.passman.keys.model

sealed interface PGPKeyAlgo
sealed interface KeyAlgo

data object RSA: PGPKeyAlgo, KeyAlgo

//object AES : Key
data object DSA : PGPKeyAlgo
data object ELGAMAL : PGPKeyAlgo
data object ECDSA : PGPKeyAlgo
data object ECDH : PGPKeyAlgo
/** Ed25519 under the pre-RFC-9580 codepoint (tag 22), paired with legacy ECDH. What this app has always generated. */
data object EDDSA : PGPKeyAlgo

/** Ed25519 under its own RFC 9580 codepoint (tag 27), paired with [X25519]. */
data object ED25519 : PGPKeyAlgo

/** X25519 key agreement under its own RFC 9580 codepoint (tag 25). Encryption only — never a primary. */
data object X25519 : PGPKeyAlgo

/** Ed448 (tag 28), paired with [X448]. Higher margin than Ed25519, thinner implementation support. */
data object ED448 : PGPKeyAlgo

/** X448 key agreement (tag 26). Encryption only — never a primary. */
data object X448 : PGPKeyAlgo
