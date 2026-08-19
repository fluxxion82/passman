package ai.passman.design.pgp

fun longToHex(value: Long): String {
    val hexChars = "0123456789ABCDEF".toCharArray()
    val result = CharArray(16)
    var temp = value

    for (i in 15 downTo 0) {
        result[i] = hexChars[(temp and 0xF).toInt()]
        temp = temp ushr 4
    }

    return result.concatToString()
}
