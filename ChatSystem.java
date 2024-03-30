import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

// Observer Pattern
interface ChatObserver {
    void update(String message);
}

class ChatArea implements ChatObserver {
    private List<User> users;
    private Map<User, List<String>> messages;

    public ChatArea() {
        users = new ArrayList<>();
        messages = new HashMap<>();
    }

    public void addUser(User user) {
        users.add(user);
        messages.put(user, new ArrayList<>());
    }

    public void sendMessage(User sender, List<User> receivers, String message) {
        for (User receiver : receivers) {
            if (users.contains(sender) && users.contains(receiver)) {
                messages.get(receiver).add(message);
                System.out.println(sender.getUsername() + " sent a message to " + receiver.getUsername());
            } else {
                System.out.println("Invalid sender or receiver");
            }
        }
    }

    // Strategy Pattern
    byte[] encryptAES(String message, String key) throws Exception {
        byte[] keyBytes = Arrays.copyOf(key.getBytes("UTF-8"), 16); // Use 128-bit (16 bytes) key for AES-128
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    private String decryptAES(byte[] encryptedMessage, String key) throws Exception {
        byte[] keyBytes = Arrays.copyOf(key.getBytes("UTF-8"), 16); // Use 128-bit (16 bytes) key for AES-128
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes, "UTF-8");
    }

    public void readMessage(User user) {
        List<String> userMessages = messages.get(user);
        if (userMessages != null) {
            System.out.println("Messages for " + user.getUsername() + ":");
            for (String encryptedMessage : userMessages) {
                try {
                    byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
                    String decryptedMessage = decryptAES(decodedMessage, user.getPrivateKey());
                    System.out.println("- " + decryptedMessage);
                } catch (Exception e) {
                    System.out.println("Decryption error: " + e.getMessage());
                }
            }
        } else {
            System.out.println("No messages for " + user.getUsername());
        }
    }

    // Observer Pattern: Update method
    @Override
    public void update(String message) {
        // Update logic for Observer
        System.out.println("Received message: " + message);
    }
}

// Factory Pattern
class ChatAreaFactory {
    public ChatArea createChatArea() {
        return new ChatArea();
    }
}

public class ChatSystem {
    private static Map<String, User> usersMap = new HashMap<>();
    private static List<ChatArea> chatSpaces = new ArrayList<>();
    private static ChatAreaFactory chatAreaFactory = new ChatAreaFactory();

    public static void registerUser(String username, String password, String privateKey) {
        if (!usersMap.containsKey(username)) {
            User newUser = new User(username, password, privateKey);
            usersMap.put(username, newUser);
            System.out.println("User registered successfully: " + username);
        } else {
            System.out.println("Username already exists");
        }
    }

    public static boolean authenticateUser(String username, String password) {
        if (usersMap.containsKey(username)) {
            User user = usersMap.get(username);
            return user.getPassword().equals(password);
        }
        return false;
    }

    public static void main(String[] args) {
        // Demo: Register users and create a chat space
        registerUser("user1", "pass123", "key123");
        registerUser("user2", "pass456", "key123");

        ChatArea chatSpace = chatAreaFactory.createChatArea();
        chatSpace.addUser(usersMap.get("user1"));
        chatSpace.addUser(usersMap.get("user2"));
        chatSpaces.add(chatSpace);

        // Demo: Sending messages and reading messages
        if (authenticateUser("user1", "pass123") && authenticateUser("user2", "pass456")) {
            User sender = usersMap.get("user1");
            User receiver = usersMap.get("user2");

            Scanner scanner = new Scanner(System.in);
            System.out.print(sender.getUsername() + ", enter your message: ");
            String message = scanner.nextLine();

            List<User> receiversList = new ArrayList<>();
            receiversList.add(receiver);

            try {
                byte[] encryptedMessage = chatSpace.encryptAES(message, sender.getPrivateKey());
                chatSpace.sendMessage(sender, receiversList, Base64.getEncoder().encodeToString(encryptedMessage));

                System.out.println(receiver.getUsername() + ", you received an encrypted message. Decrypting...");
                chatSpace.readMessage(receiver);
            } catch (Exception e) {
                System.out.println("Encryption/Decryption error: " + e.getMessage());
            }
        }
    }
}

class User {
    private String username;
    private String password;
    private String privateKey; // Adding private key attribute

    public User(String username, String password, String privateKey) {
        this.username = username;
        this.password = password;
        this.privateKey = privateKey;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}