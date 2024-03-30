import javax.crypto.*;

import java.security.*;
import java.util.*;

import javax.crypto.spec.SecretKeySpec;

// Implement AES encryption strategy
public class AESEncryptionStrategy implements EncryptionStrategy {
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    @Override
    public byte[] encrypt(String message, String key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKey = generateAESKey(key);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes());
    }

    @Override
    public String decrypt(byte[] encryptedMessage, String key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKey = generateAESKey(key);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    private SecretKeySpec generateAESKey(String key) {
        byte[] keyBytes = Arrays.copyOf(key.getBytes(), 16); // Using fixed 128-bit key size for AES-128
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }
}