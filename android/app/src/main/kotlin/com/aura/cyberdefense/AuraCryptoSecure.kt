package com.aura.cyberdefense

import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class AuraCryptoSecure private constructor() {
    private external fun decryptModelNative(
        encryptedData: ByteArray,
        keyBytes: ByteArray,
        ivBytes: ByteArray,
    ): ByteArray?

    private fun decryptWithPlatformCipher(
        encryptedData: ByteArray,
        keyBytes: ByteArray,
        ivBytes: ByteArray,
    ): ByteArray? {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(128, ivBytes),
            )
            return cipher.doFinal(encryptedData)
        } catch (_: Exception) {
            return null
        } finally {
            Arrays.fill(keyBytes, 0.toByte())
            Arrays.fill(ivBytes, 0.toByte())
        }
    }

    companion object {
        init {
            System.loadLibrary("hev-socks5-tunnel")
        }

        private val instance = AuraCryptoSecure()

        @JvmStatic
        fun decryptModel(
            encryptedData: ByteArray,
            keyBytes: ByteArray,
            ivBytes: ByteArray,
        ): ByteArray {
            try {
                require(
                    encryptedData.size >= GCM_TAG_LENGTH &&
                    keyBytes.size == 32 &&
                    ivBytes.size == GCM_IV_LENGTH,
                ) {
                    "GCM ciphertext, a 256-bit AES key, and a 12-byte nonce are required."
                }
                return requireNotNull(
                    instance.decryptModelNative(encryptedData, keyBytes, ivBytes),
                ) {
                    "Native model decryption failed."
                }
            } finally {
                Arrays.fill(keyBytes, 0.toByte())
                Arrays.fill(ivBytes, 0.toByte())
            }
        }
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
