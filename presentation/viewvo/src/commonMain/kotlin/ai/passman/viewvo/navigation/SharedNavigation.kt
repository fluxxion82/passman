package ai.passman.viewvo.navigation

data object Back : TransferNavigation,
    ReconcileNavigation,
    AddPasswordNavigation,
    PgpAddUserIdNavigation,
    PgpAddSubkeyNavigation,
    PgpCreateKeyNavigation,
    PgpChangePasswordNavigation,
    PgpDeleteKeyNavigation,
    KeystoreNavigation,
    KeystoreDetailsNavigation

data class ErrorMessage(val message: String): PgpAddSubkeyNavigation, PgpCreateKeyNavigation
