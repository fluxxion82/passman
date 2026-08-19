package ai.passman.domain.base.model

import ai.passman.domain.exception.Failure
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

sealed class Outcome<out TResult : Any> {
    data class Success<out TResult : Any>(val value: TResult) : Outcome<TResult>()
    data class Error(val message: String, val cause: Failure) : Outcome<Nothing>()
}

@OptIn(ExperimentalContracts::class)
fun <TResult : Any> Outcome<TResult>.isSuccessful(): Boolean {
    contract {
        returns(true) implies (this@isSuccessful is Outcome.Success)
        returns(false) implies (this@isSuccessful is Outcome.Error)
    }
    return this is Outcome.Success
}
