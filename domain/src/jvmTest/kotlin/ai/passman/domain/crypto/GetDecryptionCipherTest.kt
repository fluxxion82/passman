package ai.passman.domain.crypto

import ai.passman.domain.keystore.GetDecryptionCipher
import ai.passman.domain.keystore.service.CipherService
import io.mockk.MockKAnnotations
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Before

class GetDecryptionCipherTest {

    @RelaxedMockK
    private lateinit var cipherService: CipherService

    private lateinit var usecase: GetDecryptionCipher

    @Before
    fun setUp() {
        MockKAnnotations.init(this)
        usecase = GetDecryptionCipher(cipherService)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

//    @Test
//    fun `get cipher for decryption`() = runBlockingTest {
//        usecase(any())
//        coVerify(exactly = 1) { cipherService.getInitializedCipherForDecryption(any()) }
//    }
}
