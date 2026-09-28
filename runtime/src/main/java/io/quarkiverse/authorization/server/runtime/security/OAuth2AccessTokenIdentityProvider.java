package io.quarkiverse.authorization.server.runtime.security;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;

/**
 * Authenticates exact locally issued access tokens against the authoritative authorization store.
 */
@Singleton
public final class OAuth2AccessTokenIdentityProvider
        implements IdentityProvider<OAuth2AccessTokenAuthenticationRequest> {
    private final OAuth2AuthorizationService authorizationService;
    private final DPoPTokenBinding dpop;

    @Inject
    public OAuth2AccessTokenIdentityProvider(
            OAuth2AuthorizationService authorizationService, DPoPTokenBinding dpop) {
        this.authorizationService = authorizationService;
        this.dpop = dpop;
    }

    @Override
    public Class<OAuth2AccessTokenAuthenticationRequest> getRequestType() {
        return OAuth2AccessTokenAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(
            OAuth2AccessTokenAuthenticationRequest request, AuthenticationRequestContext context) {
        return VertxContextSupport.executeBlocking(() -> authenticateToken(request));
    }

    // The lazy Quarkus boundary schedules work after the Uni has been assembled,
    // preventing callback context capture from racing with worker scope activation.
    SecurityIdentity authenticateToken(OAuth2AccessTokenAuthenticationRequest request) {
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                request.getToken().getToken(), OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null
                || authorization.getAccessToken() == null
                || !authorization.getAccessToken().isActive()
                || !request.getToken()
                        .getToken()
                        .equals(authorization.getAccessToken().getToken().getTokenValue())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        var identity = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(authorization.getPrincipalName()))
                .addCredential(request.getToken());
        if (OAuth2AccessTokenAuthenticationRequest.DPOP.equals(request.getToken().getType())) {
            DPoPProof proof = this.dpop.verifyAccessToken(request.getProof(), authorization.getAccessToken());
            this.dpop.claim(request.getProof(), proof);
            // Keep the verified proof on this identity only; it is not authorization/JDBC state.
            identity.addAttribute(DPoPProof.class.getName(), proof);
        } else if (!OAuth2AccessTokenAuthenticationRequest.BEARER.equals(
                request.getToken().getType())
                || DPoPTokenBinding.isBound(authorization.getAccessToken())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        return identity.build();
    }
}
