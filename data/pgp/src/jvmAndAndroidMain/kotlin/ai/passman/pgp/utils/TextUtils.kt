package ai.passman.pgp.utils

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator

object TextUtils {
    fun readInputLine(bOut: ByteArrayOutputStream, fIn: InputStream): Int {
        bOut.reset()
        var lookAhead = -1
        var ch: Int
        while (fIn.read().also { ch = it } >= 0) {
            bOut.write(ch)
            if (ch == '\r'.code || ch == '\n'.code) {
                lookAhead = readPassedEOL(bOut, ch, fIn)
                break
            }
        }
        return lookAhead
    }

    fun readInputLine(bOut: ByteArrayOutputStream, lookAhead: Int, fIn: InputStream): Int {
        var readAhead = lookAhead
        bOut.reset()
        var ch = lookAhead
        do {
            bOut.write(ch)
            if (ch == '\r'.code || ch == '\n'.code) {
                readAhead = readPassedEOL(bOut, ch, fIn)
                break
            }
        } while (fIn.read().also { ch = it } >= 0)
        if (ch < 0) {
            readAhead = -1
        }
        return readAhead
    }

    fun processLine(sig: PGPSignature, line: ByteArray) {
        val length = getLengthWithoutWhiteSpace(line)
        if (length > 0) {
            sig.update(line, 0, length)
        }
    }

    fun processLine(aOut: OutputStream, sGen: PGPSignatureGenerator, line: ByteArray) {
        // note: trailing white space needs to be removed from the end of
        // each line for signature calculation RFC 4880 Section 7.1
        val length = getLengthWithoutWhiteSpace(line)
        if (length > 0) {
            sGen.update(line, 0, length)
        }
        aOut.write(line, 0, line.size)
    }

    private fun readPassedEOL(bOut: ByteArrayOutputStream, lastCh: Int, fIn: InputStream): Int {
        var lookAhead = fIn.read()
        if (lastCh == '\r'.code && lookAhead == '\n'.code) {
            bOut.write(lookAhead)
            lookAhead = fIn.read()
        }
        return lookAhead
    }

    private fun getLengthWithoutWhiteSpace(line: ByteArray): Int {
        var end = line.size - 1
        while (end >= 0 && isWhiteSpace(line[end])) {
            end--
        }
        return end + 1
    }

    private fun isWhiteSpace(b: Byte): Boolean = isLineEnding(b) || b == '\t'.code.toByte() || b == ' '.code.toByte()

    private fun isLineEnding(b: Byte): Boolean = b == '\r'.code.toByte() || b == '\n'.code.toByte()
}
