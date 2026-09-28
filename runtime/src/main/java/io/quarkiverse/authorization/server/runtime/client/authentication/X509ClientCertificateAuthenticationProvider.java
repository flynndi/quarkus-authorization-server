package io.quarkiverse.authorization.server.runtime.client.authentication;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;

/** Authenticates TLS client certificates through the native Quarkus identity-provider chain. */
@Singleton
public final class X509ClientCertificateAuthenticationProvider
        implements IdentityProvider<X509ClientCertificateAuthenticationRequest> {
    private final RegisteredClientRepository clients;
    private final X509ClientCertificateVerifier verifier;

    @Inject
    public X509ClientCertificateAuthenticationProvider(RegisteredClientRepository clients,
            X509ClientCertificateVerifier verifier) {
        this.clients = clients;
        this.verifier = verifier;
    }

    @Override
    public Class<X509ClientCertificateAuthenticationRequest> getRequestType() {
        return X509ClientCertificateAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(X509ClientCertificateAuthenticationRequest request,
            AuthenticationRequestContext context) {
        // JDBC, remote JWKS and crypto execute with a Quarkus worker and active CDI request scope.
        return VertxContextSupport.executeBlocking(() -> {
            RegisteredClient client = this.clients.findByClientId(request.getClientId());
            if (client == null)
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            ClientAuthenticationMethod method = this.verifier.verify(client, request.getCertificate().getCertificate());
            return QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(client.getClientId()))
                    .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client)
                    .addAttribute(OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE, method)
                    .addCredential(request.getCertificate())
                    .build();
        });
    }
}
