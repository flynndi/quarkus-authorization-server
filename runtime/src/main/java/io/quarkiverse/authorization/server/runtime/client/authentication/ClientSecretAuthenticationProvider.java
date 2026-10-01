package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.time.Instant;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.ClientSecretVerifier;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * Authenticates an OAuth 2.0 client using its registered client secret.
 */
@Singleton
public final class ClientSecretAuthenticationProvider implements IdentityProvider<OAuth2ClientAuthenticationToken> {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository registeredClientRepository;
    private final ClientSecretVerifier clientSecretVerifier;
    private final ProtocolExecutor executor;

    @Inject
    public ClientSecretAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            ClientSecretVerifier clientSecretVerifier, ProtocolExecutor executor) {
        this.registeredClientRepository = registeredClientRepository;
        this.clientSecretVerifier = clientSecretVerifier;
        this.executor = executor;
    }

    @Override
    public Class<OAuth2ClientAuthenticationToken> getRequestType() {
        return OAuth2ClientAuthenticationToken.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(OAuth2ClientAuthenticationToken authentication,
            AuthenticationRequestContext context) {
        if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(authentication.getClientAuthenticationMethod())
                && !ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(authentication.getClientAuthenticationMethod())) {
            return Uni.createFrom().nullItem();
        }

        return this.executor.execute(authentication, () -> authenticateClient(authentication));
    }

    // The lazy Quarkus boundary schedules work after the Uni has been assembled,
    // preventing callback context capture from racing with worker scope activation.
    SecurityIdentity authenticateClient(OAuth2ClientAuthenticationToken authentication) {
        RegisteredClient registeredClient = this.registeredClientRepository
                .findByClientId(authentication.getPrincipal());
        if (registeredClient == null) {
            throw invalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (!registeredClient.getClientAuthenticationMethods()
                .contains(authentication.getClientAuthenticationMethod())) {
            throw invalidClient("authentication_method");
        }

        String credentials = authentication.getCredentials();
        if (credentials == null) {
            throw invalidClient("credentials");
        }
        if (!this.clientSecretVerifier.matches(credentials, registeredClient.getClientSecret())) {
            throw invalidClient(OAuth2ParameterNames.CLIENT_SECRET);
        }

        Instant secretExpiresAt = registeredClient.getClientSecretExpiresAt();
        if (secretExpiresAt != null && Instant.now().isAfter(secretExpiresAt)) {
            throw invalidClient("client_secret_expires_at");
        }

        // Carry the authenticated client and authentication method as Quarkus SecurityIdentity attributes.
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, registeredClient)
                .addAttribute(OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        authentication.getClientAuthenticationMethod())
                .build();
    }

    private static OAuth2AuthenticationException invalidClient(String parameterName) {
        return new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameterName,
                ERROR_URI));
    }
}
