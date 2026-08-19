package ai.passman.domain.pgp.model

sealed class PgpEvent {
    data object KeyCreated: PgpEvent()
    data object KeyModified: PgpEvent()
    data object UserIdModification: PgpEvent()
}
