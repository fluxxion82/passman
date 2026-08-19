package ai.passman.domain.settings.model

sealed class ReconcileAction {
    data object Merge: ReconcileAction()
    data object Overwrite: ReconcileAction()
    data object Delete: ReconcileAction()
}
