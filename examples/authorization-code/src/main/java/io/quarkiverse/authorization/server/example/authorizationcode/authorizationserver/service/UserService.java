package io.quarkiverse.authorization.server.example.authorizationcode.authorizationserver.service;

import java.util.Map;
import java.util.Set;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.example.authorizationcode.authorizationserver.user.User;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.security.AuthenticationFailedException;

@Singleton
public class UserService {
    public static final String RESOURCE_OWNER = "resource-owner";
    public static final String RESOURCE_OWNER_PASSWORD = "resource-owner-password";

    // Replace this in-memory directory with the application's user repository.
    private final Map<String, User> users = Map.of(RESOURCE_OWNER,
            new User(RESOURCE_OWNER, BcryptUtil.bcryptHash(RESOURCE_OWNER_PASSWORD),
                    Set.of("user"), Set.of("message.read")));

    public User findUser(String username) {
        User user = this.users.get(username);
        if (user == null) {
            throw new AuthenticationFailedException();
        }
        return user;
    }
}
