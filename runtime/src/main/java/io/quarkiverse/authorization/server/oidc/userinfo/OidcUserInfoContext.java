package io.quarkiverse.authorization.server.oidc.userinfo;

import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.security.identity.SecurityIdentity;

/** Validated protocol input and state passed to application policy. */
public record OidcUserInfoContext(
        SecurityIdentity principal,
        OAuth2AccessToken accessToken,
        OAuth2Authorization authorization) {
    public OidcUserInfoContext {
        Objects.requireNonNull(principal, "principal cannot be null");
        Objects.requireNonNull(accessToken, "accessToken cannot be null");
        Objects.requireNonNull(authorization, "authorization cannot be null");
    }
}
