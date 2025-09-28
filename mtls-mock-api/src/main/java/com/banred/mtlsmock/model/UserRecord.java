package com.banred.mtlsmock.model;

import java.io.Serializable;

public class UserRecord implements Serializable {
    private String username;
    private String password;
    private String[] roles;

    public UserRecord() {}
    public UserRecord(String username, String password, String[] roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    // getters y setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String[] getRoles() { return roles; }
    public void setRoles(String[] roles) { this.roles = roles; }
}
