import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


// Define EncryptionStrategy interface
interface EncryptionStrategy {
    byte[] encrypt(String message, String key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    String decrypt(byte[] encryptedMessage, String key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;
}

// Implement AES encryption strategy
class AESEncryptionStrategy implements EncryptionStrategy {
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

// Create EncryptionStrategyFactory
class EncryptionStrategyFactory {
    public EncryptionStrategy createEncryptionStrategy(String type) {
        if (type.equalsIgnoreCase("AES")) {
            return new AESEncryptionStrategy();
        } else {
            // Implement other encryption strategies here
            return null;
        }
    }
}

// Modify EncryptionManager to use EncryptionStrategy
class EncryptionManager {
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

// Observer Pattern: User as an observer
interface MessageObserver {
    void update(String message);
}

// ChatRoomManager Singleton class
class ChatRoomManager {
    private static ChatRoomManager instance;
    private List<ChatArea> chatSpaces;

    private ChatRoomManager() {
        chatSpaces = new ArrayList<>();
    }

    public static ChatRoomManager getInstance() {
        if (instance == null) {
            instance = new ChatRoomManager();
        }
        return instance;
    }

    public ChatArea createChatRoom() {
        ChatArea chatArea = new ChatArea();
        chatSpaces.add(chatArea);
        return chatArea;
    }

    public ChatArea getChatRoom(int roomNumber) {
        if (roomNumber >= 0 && roomNumber < chatSpaces.size()) {
            return chatSpaces.get(roomNumber);
        }
        return null;
    }

    public List<ChatArea> getChatSpaces() {
        return chatSpaces;
    }
}

class ChatArea {
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

class EncryptedChatSystem {
    private static Map<String, User> usersMap = new HashMap<>();
    private static ChatRoomManager chatRoomManager = ChatRoomManager.getInstance();
    private static Scanner scanner = new Scanner(System.in);
    private static User activeUser = null;
    private static int activeRoom = -1;
    private static EncryptionManager encryptionManager; // Declare EncryptionManager // Singleton instance

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

    public static void createUser() {
        System.out.print("Enter new username: ");
        String newUsername = scanner.nextLine();
    
        System.out.print("Enter new password: ");
        String newPassword = scanner.nextLine();
    
        System.out.print("Enter private key: ");
        String newPrivateKey = scanner.nextLine();
    
        registerUser(newUsername, newPassword, newPrivateKey);

        activeUser = usersMap.get(newUsername);
        System.out.println("Active user set: " + activeUser.getUsername());
    }

    public static void switchUser() {
        if (activeUser != null) {
            System.out.print("Enter your password to switch " + activeUser.getUsername() + ": ");
            String passwordAttempt = scanner.nextLine();
            if (authenticateUser(activeUser.getUsername(), passwordAttempt)) {
                System.out.print("Enter username of the user to switch to: ");
                String newUsername = scanner.nextLine();
                User newUser = usersMap.get(newUsername);
                if (newUser != null) {
                    activeUser = newUser;
                    System.out.println("Switched to user: " + activeUser.getUsername());
                } else {
                    System.out.println("User does not exist.");
                }
            } else {
                System.out.println("Incorrect password. Cannot switch user.");
            }
        } else {
            System.out.println("No active user to switch.");
        }
    }

    public static void removeUserFromRoom(User user, int roomNumber) {
        ChatArea chatSpace = chatRoomManager.getChatRoom(roomNumber);
        if (chatSpace != null) {
            if (chatSpace.getUsers().contains(user)) {
                chatSpace.getUsers().remove(user);
                System.out.println(user.getUsername() + " removed from chat room " + roomNumber);
            } else {
                System.out.println(user.getUsername() + " is not in chat room " + roomNumber);
            }
        } else {
            System.out.println("Chat room does not exist.");
        }
    }

    public static void createChatRoom() {
        chatRoomManager.createChatRoom();
        System.out.println("New chat room created.");
    }

    public static void joinChatRoom() {
        System.out.print("Enter room number to join: ");
        int roomNumber = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        if (activeUser != null) {
            joinUserToRoom(activeUser, roomNumber);
            activeRoom = roomNumber; // Update activeRoom after joining a room
        } else {
            System.out.println("No active user to join a room.");
        }
    }

    public static void joinUserToRoom(User user, int roomNumber) {
        ChatArea chatSpace = chatRoomManager.getChatRoom(roomNumber);
        if (chatSpace != null) {
            if (!chatSpace.getUsers().contains(user)) {
                chatSpace.addUser(user);
                System.out.println(user.getUsername() + " joined chat room " + roomNumber);
            } else {
                System.out.println(user.getUsername() + " is already in chat room " + roomNumber);
            }
        } else {
            System.out.println("Chat room does not exist.");
        }
    }

    public static void listUsersInChatRoom(int roomNumber) {
        ChatArea chatSpace = chatRoomManager.getChatRoom(roomNumber);
        if (chatSpace != null) {
            System.out.println("Users in chat room " + roomNumber + ":");
            List<User> users = chatSpace.getUsers();
            for (User user : users) {
                System.out.println("- " + user.getUsername());
            }
        } else {
            System.out.println("Chat room does not exist.");
        }
    }

    public static void sendMessageToUsers(String message, List<String> receiverNames) {
        if (activeUser != null && activeRoom != -1) {
            List<User> receivers = new ArrayList<>();
            for (String name : receiverNames) {
                User receiver = usersMap.get(name.trim());
                if (receiver != null) {
                    receivers.add(receiver);
                } else {
                    System.out.println("User '" + name + "' does not exist.");
                }
            }
    
            ChatArea chatSpace = chatRoomManager.getChatRoom(activeRoom);
    
            if (!receivers.isEmpty()) {
                try {
                    byte[] encryptedMessage = EncryptionManager.encrypt(message, activeUser.getPrivateKey());
                    chatSpace.sendMessage(activeUser, receivers, Base64.getEncoder().encodeToString(encryptedMessage));
    
                    System.out.println("Message sent to selected users. Reading messages...");
                    for (User receiver : receivers) {
                        chatSpace.readMessage(receiver);
                    }
                } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                        InvalidKeyException | BadPaddingException |
                        IllegalBlockSizeException e) {
                    System.out.println("Encryption/Decryption error: " + e.getMessage());
                }
            } else {
                System.out.println("No valid users to send the message to.");
            }
        } else {
            System.out.println("You need to join a room to send messages.");
        }
    }
    

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        // Initialize encryption strategy (either AES or RSA)
        EncryptionStrategyFactory strategyFactory = new EncryptionStrategyFactory();
        EncryptionStrategy selectedStrategy = strategyFactory.createEncryptionStrategy("AES");

        // Create the Singleton instance of EncryptionManager
        encryptionManager = new EncryptionManager(selectedStrategy);

        while (running) {
            // Display user status
            if (activeUser != null) {
                System.out.println("Status: Active User - " + activeUser.getUsername() +
                                    ", Active Room - " + (activeRoom == -1 ? "Not in any room" : activeRoom));
            } else {
                System.out.println("Status: No active user or room");
            }
    
            // Display the main menu
            System.out.println("0. Create a new user");
            System.out.println("1. Create a chat room");
            System.out.println("2. Join a chat room");
            System.out.println("3. Switch between users");
            System.out.println("4. List chat rooms");
            System.out.println("5. List users in a chat room");
            System.out.println("6. Send messages");
            System.out.println("7. Exit");
    
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline
    
            switch (choice) {
                case 0:
                    createUser();
                    break;
                case 1:
                    createChatRoom();
                    break;
                case 2:
                    joinChatRoom();
                    break;
                case 3:
                    switchUser();
                    break;
                case 4:
                    System.out.println("List of chat rooms:");
                    for (int i = 0; i < chatRoomManager.getChatSpaces().size(); i++) {
                        System.out.println("Room " + i);
                    }
                    break;
                case 5:
                    if (activeRoom != -1) {
                        listUsersInChatRoom(activeRoom);
                    } else {
                        System.out.println("You are not in any room.");
                    }
                    break;
                    case 6:
                    if (activeUser != null && activeRoom != -1) {
                        Scanner messageScanner = new Scanner(System.in);
                        System.out.print("Enter your message: ");
                        String message = messageScanner.nextLine();
                
                        System.out.print("Choose users to send message to (enter usernames, comma-separated): ");
                        String receiverNamesInput = messageScanner.nextLine();
                        List<String> receiverNames = Arrays.asList(receiverNamesInput.split(","));
                
                        sendMessageToUsers(message, receiverNames);
                    } else {
                        System.out.println("You need to join a room to send messages.");
                    }
                    break;                               
                case 7:
                    running = false; // Exit the loop
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
                    break;
            }
        }
        System.out.println("Exiting the Encrypted Chat System.");
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