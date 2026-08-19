package ai.passman.domain.crypto

import ai.passman.domain.keystore.DecryptData
import ai.passman.domain.keystore.service.CipherService
import io.mockk.MockKAnnotations
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Before

class DecryptDataTest {
    @RelaxedMockK
    private lateinit var cipherService: CipherService

    private lateinit var usecase: DecryptData

    @Before
    fun setUp() {
        MockKAnnotations.init(this)
        usecase = DecryptData(cipherService)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

//    @Test
//    fun `decrypt data`() = runBlockingTest {
//        val data = DecryptData.Data(byteArrayOf(), Cipher.getInstance("RSA"))
//        usecase(data)
//        coVerify(exactly = 1) {
//            cipherService.decryptData(any(), any())
//        }
//    }
}
