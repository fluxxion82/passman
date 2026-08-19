package ai.passman.pgp.utils

import javax.security.auth.callback.Callback
import javax.security.auth.callback.CallbackHandler
import javax.security.auth.callback.PasswordCallback

class PinInputHandler(var lastPassword: CharArray) : CallbackHandler {

    override fun handle(callbacks: Array<out Callback>) {
        callbacks.forEach { cb ->
            if (cb is PasswordCallback) {
                this.lastPassword = "password".toCharArray()
                cb.password = this.lastPassword
            }
        }
    }
}
