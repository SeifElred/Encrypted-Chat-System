import java.util.*;

public class ChatRoomManager {
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
