import java.security.*;
import java.util.*;

import javax.crypto.*;

public class ChatArea {
    private List<User> users;
    private Map<User, List<String>> messages;
    private List<MessageObserver> observers;

    public ChatArea() {
        users = new ArrayList<>();
        messages = new HashMap<>();
        observers = new ArrayList<>();
    }

    public void addObserver(MessageObserver observer) {
        observers.add(observer);
    }

    public void removeObserver(MessageObserver observer) {
        observers.remove(observer);
    }

    public void notifyObservers(String message) {
        for (MessageObserver observer : observers) {
            observer.update(message);
        }
    }

    public void addUser(User user) {
        users.add(user);
        messages.put(user, new ArrayList<>());
    }

    public List<User> getUsers() {
        return users;
    }

    public void sendMultiUserMessage(User sender, String message) {
        for (User user : users) {
            if (!user.equals(sender)) {
                messages.get(user).add(message);
                System.out.println(sender.getUsername() + " sent a message to " + user.getUsername());
            }
        }
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

    public void readMessage(User user) {
        List<String> userMessages = messages.get(user);
        if (userMessages != null) {
            System.out.println("Messages for " + user.getUsername() + ":");
            for (String encryptedMessage : userMessages) {
                try {
                    byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
                    String decryptedMessage = EncryptionManager.decrypt(decodedMessage, user.getPrivateKey());
                    System.out.println("- " + decryptedMessage);
                } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                        InvalidKeyException | BadPaddingException |
                        IllegalBlockSizeException e) {
                    System.out.println("Decryption error: " + e.getMessage());
                }
            }
        } else {
            System.out.println("No messages for " + user.getUsername());
        }
    }
}
