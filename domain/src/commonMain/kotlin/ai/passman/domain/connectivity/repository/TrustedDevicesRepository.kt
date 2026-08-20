package ai.passman.domain.connectivity.repository

import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.TrustedDevice
import kotlinx.coroutines.flow.Flow

interface TrustedDevicesRepository {
    fun observeAll(): Flow<List<TrustedDevice>>
    suspend fun getAll(): List<TrustedDevice>

    /**
     * Persists [device] under [expectedOwner], replacing any entry with the same name.
     *
     * [expectedOwner] is *whose* peer material [device] is — the account and session the pairing was
     * attested to under, carried from wherever that was decided rather than sampled again here. For
     * a pairing ceremony that is the owner it was begun under, held in
     * [ai.passman.domain.connectivity.PendingPairingState]; for a caller that carries no
     * ceremony it is the account signed in when the call was made. The store compares it against
     * its own resolution of the signed-in account **under its write lock**, and a mismatch drops the
     * write.
     *
     * Passing a fresh sample taken next to this call would defeat the point. Two samples of "who is
     * signed in", taken either side of a gap, agree with each other whenever the switch lands
     * outside that gap and say nothing about the account the material actually belongs to: a
     * `LoginUser` with no logout in between moves the account without touching the session, so a
     * caller that validated as A and a store that samples B twice both see nothing wrong, and A's
     * peer material lands in B's store. Naming the owner is what makes the comparison meaningful —
     * the store checks the write against the identity the material came from, not against a second
     * reading of the clock.
     *
     * @return whether the pairing actually reached storage. It genuinely can come back false —
     * nobody signed in, the account moved away from [expectedOwner], or the account's encrypted
     * store would not initialise — and the entry it carries is the peer's mTLS pin and PQ keys.
     * Reporting a dropped write as success is how a user is told a device is paired while only the
     * *other* side trusts them, which is a pairing that silently never works.
     */
    suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner): Boolean
    suspend fun remove(name: String)

    /**
     * Resolves a **typed address** to the one pairing that claims it, or null when no pairing does
     * — or when more than one does.
     *
     * This is not a device lookup, and it is deliberately no longer used as one. [TrustedDevice] has
     * no id: [TrustedDevice.name] is its identity key, and nothing keeps two records from holding
     * the same [TrustedDevice.lastHost] — [add] dedupes on name only, [updateHost] repoints on name
     * only with no collision check, and re-pairing the same physical peer under a new name yields a
     * second record with the same host *and* the same fingerprint. A caller that already holds the
     * device the user chose must carry that record through rather than re-derive it from an address:
     * every consumer that re-derived it (the last-sync stamp, the mTLS pin, the sync log) could
     * silently land on the wrong record, which is the whole reason the sync path now threads
     * [TrustedDevice] end to end.
     *
     * What is left is the case that genuinely has no device to carry: an address the user typed into
     * Settings > Transfer's manual address box. There, refusing an ambiguous host is the only honest
     * answer — picking a first match would pin one of two indistinguishable pairings' SPKI on a
     * coin-flip, and the failure that follows would be unexplainable to the user. Null instead lets
     * the caller say "that address does not identify one paired device".
     */
    suspend fun getByHost(host: String): TrustedDevice?
    suspend fun updateLastSync(name: String, host: String, timestampMs: Long)

    /** Repoints [name]'s pairing at a new address (the device moved on the LAN). Keys untouched. */
    suspend fun updateHost(name: String, host: String)
    suspend fun updateAllowedOps(name: String, allowedOps: Set<String>)
    suspend fun markSignedHybridPairingsForReverification()
}
