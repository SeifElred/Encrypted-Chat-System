// Create EncryptionStrategyFactory
public class EncryptionStrategyFactory {
    public EncryptionStrategy createEncryptionStrategy(String type) {
        if (type.equalsIgnoreCase("AES")) {
            return new AESEncryptionStrategy();
        } else {
            // Implement other encryption strategies here
            return null;
        }
    }
}