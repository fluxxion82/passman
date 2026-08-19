package ai.passman.pgp

import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.util.*

class TestKeyStore : KeyStoreSpi() {
    private var wrapped: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())

    override fun engineIsKeyEntry(alias: String?) = wrapped.isKeyEntry(alias)
    override fun engineIsCertificateEntry(alias: String?) = wrapped.isCertificateEntry(alias)
    override fun engineGetCertificateAlias(cert: Certificate?): String = wrapped.getCertificateAlias(cert)
    override fun engineStore(stream: OutputStream?, password: CharArray?) = wrapped.store(stream, password)
    override fun engineLoad(stream: InputStream?, password: CharArray?) = wrapped.load(stream, password)
    override fun engineGetKey(alias: String?, password: CharArray?) = wrapped.getKey(alias, password)
    override fun engineGetCertificateChain(alias: String?): Array<Certificate> = wrapped.getCertificateChain(alias)
    override fun engineGetCertificate(alias: String?): Certificate = wrapped.getCertificate(alias)
    override fun engineGetCreationDate(alias: String?): Date = wrapped.getCreationDate(alias)
    override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) =
        wrapped.setKeyEntry(alias, key, password, chain)
    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) =
        wrapped.setKeyEntry(alias, key, chain)
    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) = wrapped.setCertificateEntry(alias, cert)
    override fun engineDeleteEntry(alias: String?) = wrapped.deleteEntry(alias)
    override fun engineAliases(): Enumeration<String> = wrapped.aliases()
    override fun engineContainsAlias(alias: String?): Boolean = wrapped.containsAlias(alias)
    override fun engineSize(): Int = wrapped.size()
}
