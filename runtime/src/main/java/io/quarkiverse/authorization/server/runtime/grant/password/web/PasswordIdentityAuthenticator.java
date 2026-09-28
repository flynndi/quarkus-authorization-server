package io.quarkiverse.authorization.server.runtime.grant.password.web;

import java.util.Arrays;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.grant.password.PasswordGrantRequest;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/** Bridges the Password HTTP grant to Quarkus user authentication, without blocking on the Uni. */
@Singleton
public final class PasswordIdentityAuthenticator {
    private final IdentityProviderManager identities;

    @Inject
    public PasswordIdentityAuthenticator(IdentityProviderManager identities) {
        this.identities = identities;
    }

    public Uni<SecurityIdentity> authenticate(PasswordGrantRequest grant, RoutingContext context) {
        return Uni.createFrom()
                .deferred(
                        () -> {
                            char[] password = grant.getPassword().toCharArray();
                            UsernamePasswordAuthenticationRequest request = new UsernamePasswordAuthenticationRequest(
                                    grant.getUsername(), new PasswordCredential(password));
                            grant.getAdditionalParameters().forEach(request::setAttribute);
                            if (context != null) {
                                HttpSecurityUtils.setRoutingContextAttribute(request, context);
                            }
                            return Uni.createFrom()
                                    .deferred(() -> this.identities.authenticate(request))
                                    .onFailure()
                                    .transform(PasswordIdentityAuthenticator::invalidGrant)
                                    .onItem()
                                    .ifNull()
                                    .failWith(() -> invalidGrant(null))
                                    .eventually(() -> Arrays.fill(password, '\0'));
                        });
    }

    private static OAuth2AuthenticationException invalidGrant(Throwable cause) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), cause);
    }
}
