//package ai.passman.keystore
//
//import ai.passman.logging.KLogger
//import ai.passman.domain.base.CoroutinesContextFacade
//import ai.passman.domain.base.model.Outcome
//import ai.passman.domain.keystore.model.KeyStoreInfo
//import ai.passman.domain.keystore.model.KeystoreFailure
//import android.os.Environment
//import android.security.keystore.KeyGenParameterSpec
//import android.security.keystore.KeyProperties
//import kotlinx.coroutines.withContext
//import java.io.File
//import java.security.KeyStore
//import javax.crypto.KeyGenerator
//
//class AndroidKeyStoreClient(
//    private val coroutinesContextFacade: CoroutinesContextFacade,
//): KeystoreClient {
//
//    override suspend fun createKeyStore(keyStoreInfo: KeyStoreInfo): KeyStore =
//        withContext(coroutinesContextFacade.io) {
//            KLogger.d { "external file path: ${keyStoreInfo.path}" }
//            val sdcard = Environment.getExternalStorageDirectory()
//            val folder = File(sdcard, keyStoreInfo.path)
//            if (!folder.exists()) {
//                folder.mkdir()
//            }
//
//            val external = File(keyStoreInfo.path, keyStoreInfo.name)
//            KLogger.d { "external file: $external" }
//            if (!external.exists()) {
//                KLogger.d { "create new file" }
//                external.createNewFile()
//            }
//
//            // JKS, PKCS12, BKS, AndroidKeyStore
//            // i think only able to use BKS right now
//            // if (keyStoreInfo.type != KeyStoreType.ANDROID) {
//            val keyStore = runCatching {
//                val builder = KeyStore.Builder.newInstance(
//                    keyStoreInfo.type.type,
//                    null,
//                    external,
//                    KeyStore.PasswordProtection(keyStoreInfo.keystorePassword.toCharArray())
//                )
//
//                builder.keyStore
//            }.getOrElse {
//                KLogger.e(it) { "failed to build keystore" }
//                KeyStore.getInstance(keyStoreInfo.type.type)
//                /// keyStore.load(null, keyStoreInfo.password)
//            }
////                } else {
////                    keyStore.load(external.inputStream(), keyStoreInfo.password)
////                }
//
//            keyStore.aliases().toList().forEach {
//                KLogger.d { "alias: $it" }
//                // keyStore.deleteEntry(it)
//            }
//
//            KLogger.d { "new keystore ${keyStoreInfo.name} at location: ${keyStoreInfo.path}" }
//
//            keyStore
//        }
//
//    override suspend fun getNewKeystoreKey(keyStoreInfo: KeyStoreInfo, keyName: String) = withContext(coroutinesContextFacade.io) {
//        runCatching {
//            val keyStore = KeyStore.getInstance("AndroidKeyStore")
//            keyStore.load(null)
//            val keyGenerator = KeyGenerator.getInstance(
//                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
//            )
//
//            // Set the alias of the entry in Android KeyStore where the key will appear
//            // and the constrains (purposes) in the constructor of the Builder
//            keyGenerator.init(
//                KeyGenParameterSpec.Builder(
//                    keyName,
//                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
//                )
//                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                    .setUserAuthenticationRequired(true) // Require that the user has unlocked in the last 30 seconds
//                    .setUserAuthenticationValidityDurationSeconds(30)
//                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                    .build()
//            )
//            val key = keyGenerator.generateKey()
//
//            Outcome.Success(key)
//        }.getOrElse {
//            Outcome.Error("Failed to generate new master key", KeystoreFailure.KeyGenerationFailure)
//        }
//    }
//}
