package io.quarkiverse.authorization.server.it.entity;

public class User {
    long id;

    String username;

    String displayName;

    String password;

    boolean enabled;

    public User() {
    }

    public User(long id, String username, String displayName, String password, boolean enabled) {
        this.id = id;
        this.username = username;
        this.displayName = displayName;
        this.password = password;
        this.enabled = enabled;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
