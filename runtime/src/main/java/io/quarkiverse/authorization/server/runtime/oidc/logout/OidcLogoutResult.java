package io.quarkiverse.authorization.server.runtime.oidc.logout;

import java.util.Objects;

import io.quarkus.security.identity.SecurityIdentity;

/** Validated logout target and identity for the HTTP session adapter. */
public record OidcLogoutResult(
        SecurityIdentity principal, String postLogoutRedirectUri, String state) {
    public OidcLogoutResult {
        Objects.requireNonNull(principal, "principal cannot be null");
    }
}
