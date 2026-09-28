package io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.user;

import java.util.Set;

public record User(String username, String passwordHash, Set<String> roles, Set<String> permissions) {
}
