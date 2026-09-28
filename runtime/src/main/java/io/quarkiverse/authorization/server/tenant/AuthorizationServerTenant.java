package io.quarkiverse.authorization.server.tenant;

import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;

/** Application-owned components for one configured issuer, supplied as an @Identifier(tenantId) CDI bean. */
public record AuthorizationServerTenant(RegisteredClientRepository clients, OAuth2AuthorizationService authorizations,
        OAuth2AuthorizationConsentService consents, AuthorizationServerKeySource signingKeys) {
    public AuthorizationServerTenant {
        Objects.requireNonNull(clients, "clients");
        Objects.requireNonNull(authorizations, "authorizations");
        Objects.requireNonNull(consents, "consents");
        Objects.requireNonNull(signingKeys, "signingKeys");
    }
}
