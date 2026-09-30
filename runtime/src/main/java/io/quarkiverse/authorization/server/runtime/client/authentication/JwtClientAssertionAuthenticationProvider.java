package io.quarkiverse.authorization.server.runtime.client.authentication;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/** Authenticates JWT client assertions through the native Quarkus identity-provider chain. */
@Singleton
public final class JwtClientAssertionAuthenticationProvider
        implements IdentityProvider<JwtClientAssertionAuthenticationRequest> {
    private final RegisteredClientRepository clients;
    private final JwtClientAssertionVerifier verifier;
    private final ProtocolExecutor executor;

    @Inject
    public JwtClientAssertionAuthenticationProvider(RegisteredClientRepository clients, JwtClientAssertionVerifier verifier,
            ProtocolExecutor executor) {
        this.clients = clients;
        this.verifier = verifier;
        this.executor = executor;
    }

    @Override
    public Class<JwtClientAssertionAuthenticationRequest> getRequestType() {
        return JwtClientAssertionAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(JwtClientAssertionAuthenticationRequest request,
            AuthenticationRequestContext context) {
        // JDBC, remote JWKS and crypto execute with a Quarkus worker and active CDI request scope.
        return this.executor.execute(request, () -> {
            RegisteredClient client = this.clients.findByClientId(request.getClientId());
            if (client == null)
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            ClientAuthenticationMethod method = this.verifier.verify(client, request.getAssertion());
            return QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(client.getClientId()))
                    .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client)
                    .addAttribute(OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE, method)
                    .build();
        });
    }
}
