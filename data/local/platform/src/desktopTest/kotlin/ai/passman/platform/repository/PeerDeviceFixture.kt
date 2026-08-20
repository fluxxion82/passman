package ai.passman.platform.repository

import ai.passman.domain.connectivity.model.TrustedDevice

/**
 * A paired peer at [host], for the vault tests that only need *some* sync target to aim a push or
 * pull at.
 *
 * The sync repository methods take the [TrustedDevice] the chooser handed the session rather than a
 * host string, because the transport pins that record's SPKI and two pairings can hold one address
 * (see `TrustedDevicesRepository.getByHost`). None of these tests exercise that distinction — they
 * are about vault merging and decoding — so they get a record built from the address they already
 * name, and the pairing-identity behaviour is pinned where it belongs, in `SyncSessionTest` and
 * `LocalTrustedDevicesRepositoryTest`.
 */
internal fun peerDevice(host: String): TrustedDevice =
    TrustedDevice(name = "peer-$host", fingerprint = "fp-$host", lastHost = host)
