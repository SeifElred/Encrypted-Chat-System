## Encrypted Chat System

### Overview

The **Encrypted Chat System** is a Java-based application that provides secure messaging functionalities using the Advanced Encryption Standard (AES) algorithm. It enables users to register, authenticate, create and join chat rooms, send encrypted messages to multiple users, and switch between active users. The system incorporates design patterns such as **Strategy** and **Singleton** to manage encryption strategies efficiently and ensure single-instance managers, respectively. 

### Features

1. **User Management**
   - User registration with a unique username, password, and private key.
   - User authentication to verify credentials before allowing access.
   - Switching between active users for multi-user testing.

2. **Chat Room Management**
   - Creation of new chat rooms.
   - Joining existing chat rooms by room number.
   - Listing all chat rooms and users within a specific room.

3. **Secure Messaging**
   - Encryption and decryption of messages using AES encryption.
   - Sending encrypted messages to multiple users within a chat room.
   - Reading and displaying decrypted messages for individual users.

4. **Design Patterns**
   - **Strategy Pattern**: Implements different encryption strategies (currently supports only AES).
   - **Singleton Pattern**: Ensures a single instance of the ChatRoomManager and EncryptionManager.

### Encryption Strategy

The application currently supports the AES encryption strategy for encrypting and decrypting messages. The `AESEncryptionStrategy` class implements the `EncryptionStrategy` interface, providing methods to encrypt and decrypt messages using AES with ECB mode and PKCS5 padding. The `EncryptionStrategyFactory` class facilitates the creation of encryption strategies based on the specified type (e.g., "AES").

### Chat Room Management

The `ChatRoomManager` class is implemented as a Singleton and manages the creation and retrieval of chat rooms. Each chat room (`ChatArea`) maintains a list of users, messages, and message observers. Users can join chat rooms, send messages to multiple users, and read messages sent to them.

### Usage

1. **Registration and Authentication**
   - Users can register with a unique username, password, and private key.
   - Authentication ensures that only registered users can access the system.

2. **Creating and Joining Chat Rooms**
   - Users can create new chat rooms.
   - Existing chat rooms can be joined using the room number.

3. **Sending and Receiving Messages**
   - Messages are encrypted before sending using AES.
   - Decryption of messages allows users to read the original content.

4. **Switching Users**
   - Active users can switch to other registered users after authentication.

### Dependencies

- Java 8 or higher
- Java Cryptography Extension (JCE) for AES encryption

### Getting Started

To run the Encrypted Chat System:

1. Clone the repository to your local machine.
2. Compile and run the `EncryptedChatSystem.java` file using a Java compiler.
3. Follow the on-screen instructions to navigate the application and test its functionalities.

### Future Enhancements

- Support for additional encryption algorithms (e.g., RSA).
- Implementing a graphical user interface (GUI) for better user experience.
- Adding error handling and validation to improve robustness.

### Contributing

Contributions to the Encrypted Chat System are welcome! Please fork the repository, make your changes, and submit a pull request for review.

### License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

For any questions or feedback, please contact  [Seif Elredeini]](info@seifelredeini.com).