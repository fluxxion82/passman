package ai.passman.domain.exception

sealed class Failure {
    class NetworkConnection : Failure()
    class ServerError(val status: Int) : Failure()

    /** * Extend this class for feature specific failures.*/
    abstract class FeatureFailure : Failure()
}
