package io.quarkiverse.authorization.server.client.registration;

import java.util.Objects;
import java.util.Set;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkus.security.identity.SecurityIdentity;

/** Client-supplied registration values; identifiers and credentials are issued by the server. */
public record OAuth2ClientRegistrationRequest(SecurityIdentity principal, String clientName,
        ClientAuthenticationMethod authenticationMethod, Set<AuthorizationGrantType> grantTypes,
        Set<String> redirectUris, Set<String> scopes) {
    public OAuth2ClientRegistrationRequest {
        Objects.requireNonNull(principal, "principal");
        Objects.requireNonNull(authenticationMethod, "authenticationMethod");
        grantTypes = Set.copyOf(grantTypes);
        redirectUris = Set.copyOf(redirectUris);
        scopes = Set.copyOf(scopes);
    }
}
