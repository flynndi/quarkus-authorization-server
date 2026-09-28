package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

/** Reference returned to a client after its authorization request has been validated and saved. */
public record PushedAuthorizationResponse(String requestUri, long expiresIn) {
}
