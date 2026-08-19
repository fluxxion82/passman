package ai.passman.domain.crypto

import ai.passman.domain.keystore.GetEncryptionCipher
import ai.passman.domain.keystore.service.CipherService
import io.mockk.MockKAnnotations
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Before

class GetEncryptionCipherTest {

    @RelaxedMockK
    private lateinit var cipherService: CipherService

    private lateinit var usecase: GetEncryptionCipher

    @Before
    fun setUp() {
        MockKAnnotations.init(this)
        usecase = GetEncryptionCipher(cipherService)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

//    @Test
//    fun `get cipher for decryption`() = runBlockingTest {
//        usecase(any())
//        coVerify(exactly = 1) { cipherService.getInitializedCipherForEncryption(any()) }
//    }
}
