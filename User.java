public class User {
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
