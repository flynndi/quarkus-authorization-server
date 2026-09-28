package io.quarkiverse.authorization.server.runtime.client.authentication;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;

/** Resolves a registered public client. Each grant validates its own authorization proof. */
@Singleton
public final class PublicClientAuthenticationProvider
        implements IdentityProvider<OAuth2ClientAuthenticationToken> {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository registeredClientRepository;

    @Inject
    public PublicClientAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Class<OAuth2ClientAuthenticationToken> getRequestType() {
        return OAuth2ClientAuthenticationToken.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(OAuth2ClientAuthenticationToken authentication,
            AuthenticationRequestContext context) {
        if (!ClientAuthenticationMethod.NONE.equals(authentication.getClientAuthenticationMethod())) {
            return Uni.createFrom().nullItem();
        }

        return VertxContextSupport.executeBlocking(() -> authenticateClient(authentication));
    }

    // The lazy Quarkus boundary schedules work after the Uni has been assembled,
    // preventing callback context capture from racing with worker scope activation.
    SecurityIdentity authenticateClient(OAuth2ClientAuthenticationToken authentication) {
        RegisteredClient registeredClient = this.registeredClientRepository
                .findByClientId(authentication.getPrincipal());
        if (registeredClient == null) {
            throw invalidClient(OAuth2ParameterNames.CLIENT_ID);
        }
        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throw invalidClient("authentication_method");
        }

        // NONE identifies a client; possession of an authorization code, refresh token or
        // device code must still be established by the corresponding grant.
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        registeredClient)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        ClientAuthenticationMethod.NONE)
                .build();
    }

    private static OAuth2AuthenticationException invalidClient(String parameterName) {
        return new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameterName,
                ERROR_URI));
    }
}
