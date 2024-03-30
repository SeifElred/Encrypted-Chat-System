import java.util.*;

class ChatUser {
    private final String username;
    final Map<String, String> privateKeys;

    public ChatUser(String username) {
        this.username = username;
        this.privateKeys = new HashMap<>();
    }

    public void addPrivateKey(String recipient, String privateKey) {
        privateKeys.put(recipient, privateKey);
    }

    public String getUsername() {
        return username;
    }
}

class ChatSpace {
    private final List<ChatUser> users = new ArrayList<>();

    public void addUser(ChatUser user) {
        users.add(user);
    }

    public void sendMessage(ChatUser sender, String message, String recipient) {
        String encryptedMessage = encryptMessage(message, sender.getUsername(), recipient);
        if (recipient.equals("All")) {
            notifyAllUsers(sender, encryptedMessage);
        } else {
            notifySpecificUser(sender, recipient, encryptedMessage);
        }
    }

    private String encryptMessage(String message, String senderUsername, String recipientUsername) {
        ChatUser senderUser = findUserByUsername(senderUsername);
        ChatUser recipientUser = findUserByUsername(recipientUsername);

        Map<String, String> senderPrivateKeys = senderUser != null ? senderUser.privateKeys : null;
        Map<String, String> recipientPrivateKeys = recipientUser != null ? recipientUser.privateKeys : null;

        if (senderPrivateKeys != null && recipientPrivateKeys != null) {
            String senderPrivateKey = senderPrivateKeys.get(recipientUsername);
            String recipientPrivateKey = recipientPrivateKeys.get(senderUsername);

            if (senderPrivateKey != null && recipientPrivateKey != null) {
                StringBuilder encrypted = new StringBuilder();
                for (int i = 0; i < message.length(); i++) {
                    encrypted.append((char) (message.charAt(i) ^ senderPrivateKey.charAt(i % senderPrivateKey.length()) ^ recipientPrivateKey.charAt(i % recipientPrivateKey.length())));
                }
                return encrypted.toString();
            } else {
                return "Encryption keys not found. Message cannot be sent.";
            }
        } else {
            return "Users not found. Message cannot be sent.";
        }
    }

    private void notifyAllUsers(ChatUser sender, String message) {
        for (ChatUser user : users) {
            if (!user.equals(sender)) {
                System.out.println(user.getUsername() + " received: " + message);
            }
        }
    }

    private void notifySpecificUser(ChatUser sender, String recipient, String message) {
        ChatUser recipientUser = findUserByUsername(recipient);
        if (recipientUser != null) {
            System.out.println(recipientUser.getUsername() + " received: " + message);
        } else {
            System.out.println("Recipient " + recipient + " not found.");
        }
    }

    private ChatUser findUserByUsername(String username) {
        for (ChatUser user : users) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }
}

public class EncryptedChatSystem {
    public static void main(String[] args) {
        ChatSpace space = new ChatSpace();

        ChatUser user1 = new ChatUser("Alice");
        ChatUser user2 = new ChatUser("Bob");
        ChatUser user3 = new ChatUser("Eve");

        user1.addPrivateKey("Bob", "key1");
        user1.addPrivateKey("Eve", "key2");
        user2.addPrivateKey("Alice", "key1");
        user2.addPrivateKey("Eve", "key3");
        user3.addPrivateKey("Alice", "key2");
        
        user3.addPrivateKey("Bob", "key3");

        space.addUser(user1);
        space.addUser(user2);
        space.addUser(user3);

        space.sendMessage(user1, "Hi Bob, this is Alice!", "Bob");
        space.sendMessage(user2, "Hello everyone!", "All");
        space.sendMessage(user3, "This won't reach anyone", "Mallory");
    }
}