import java.security.*;

import javax.crypto.*;

public class EncryptionManager {
    private static EncryptionStrategy encryptionStrategy;

    public EncryptionManager(EncryptionStrategy strategy) {
        this.encryptionStrategy = strategy;
    }

    public static byte[] encrypt(String message, String key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptionStrategy.encrypt(message, key);
    }

    public static String decrypt(byte[] encryptedMessage, String key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptionStrategy.decrypt(encryptedMessage, key);
    }
}