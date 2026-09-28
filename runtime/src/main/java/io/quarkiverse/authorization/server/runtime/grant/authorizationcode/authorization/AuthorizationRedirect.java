package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

/** A redirect target that has passed client registration checks, with the original client state. */
public record AuthorizationRedirect(String uri, String state) {
    public AuthorizationRedirect {
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException("uri cannot be empty");
        }
    }
}
