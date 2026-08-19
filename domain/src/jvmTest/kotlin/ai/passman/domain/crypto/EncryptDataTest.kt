// package ai.passman.domain.crypto

// class EncryptDataTest {

//    private lateinit var cipherService: CipherService
//
//    private lateinit var usecase: EncryptData
//
//    @Mock
//    private lateinit var cipher: Cipher
//
//    @Before
//    fun setUp() {
//        cipherService = mock {
//            onBlocking {
//                encryptData(any(), any())
//            } doReturn Outcome.Success(EncryptedData(byteArrayOf(), byteArrayOf()))
//        }
//
//        usecase = EncryptData(cipherService)
//    }

//    @Test
//    fun `encrypt data`() {
//        runBlocking {
//            usecase.invoke(EncryptData.Data("hello".toByteArray(), cipher))
//        }
//
//        verifyBlocking(cipherService) {
//            encryptData("hello".toByteArray(), cipher)
//        }
//
//        runBlocking {
//            cipherService.getInitializedCipherForEncryption(
//                EncryptInfo(
//                    KeyStoreInfo("path", "keystoreName", "".toCharArray(), KeyStoreType.ANDROID),
//                    "testAlias"
//                )
//            )
//        }
//    }
// }
