package io.quarkiverse.authorization.server.runtime.grant.refreshtoken;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;

/** Validates and refreshes an existing authorization. */
@Singleton
public final class RefreshTokenGrant {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext authorizationServerContext;
    private final DPoPTokenBinding dpop;

    @Inject
    public RefreshTokenGrant(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            AuthorizationServerContext authorizationServerContext,
            DPoPTokenBinding dpop) {
        this.dpop = Objects.requireNonNull(dpop);
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.tokenGenerator = Objects.requireNonNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationServerContext = Objects.requireNonNull(
                authorizationServerContext, "authorizationServerContext cannot be null");
    }

    /**
     * Synchronous protocol work; the HTTP entry point supplies worker execution and a CDI request
     * context.
     */
    public TokenIssuanceResult issueTokens(RefreshTokenRequest request) {
        return issueTokens(request, null);
    }

    public TokenIssuanceResult issueTokens(
            RefreshTokenRequest request, DPoPProofRequest proofRequest) {
        SecurityIdentity clientPrincipal = request.getClientPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        if (clientPrincipal.isAnonymous() || registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                request.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (!refreshToken.isActive()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        Set<String> scopes = request.getScopes();
        Set<String> authorizedScopes = authorization.getAuthorizedScopes();
        if (!authorizedScopes.containsAll(scopes)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
        if (scopes.isEmpty()) {
            scopes = authorizedScopes;
        }

        // Public refresh authorization follows the persisted key binding, regardless of the
        // original grant. Client identification alone never authorizes an unbound refresh token.
        Object storedJkt = refreshToken.getMetadata(DPoPTokenBinding.REFRESH_JKT_METADATA);
        boolean publicClient = ClientAuthenticationMethod.NONE.equals(
                clientPrincipal.getAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE));
        if ((storedJkt != null
                && (!(storedJkt instanceof String jkt)
                        || !jkt.matches("[A-Za-z0-9_-]{43}")))
                || (publicClient && storedJkt == null))
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        DPoPProof proof = this.dpop.verify(proofRequest, (String) storedJkt);
        this.dpop.claim(proofRequest, proof);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authorization.getAttribute(SecurityIdentity.class.getName()))
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorization(authorization)
                .authorizedScopes(scopes)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(request);

        if (proof != null)
            tokenContextBuilder.put(DPoPProof.class, proof);
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate the access token.",
                            ERROR_URI));
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(
                authorizationBuilder, generatedAccessToken, tokenContext);

        OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
        if (!registeredClient.getTokenSettings().isReuseRefreshTokens()) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(
                                OAuth2ErrorCodes.SERVER_ERROR,
                                "The token generator failed to generate the refresh token.",
                                ERROR_URI));
            }
            currentRefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.token(
                    currentRefreshToken,
                    metadata -> {
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
                        if (storedJkt != null)
                            metadata.put(DPoPTokenBinding.REFRESH_JKT_METADATA, storedJkt);
                        else
                            metadata.remove(DPoPTokenBinding.REFRESH_JKT_METADATA);
                    });
        }
        OidcIdToken idToken = null;
        // ID Token eligibility uses the original authorization scopes, even when the refreshed
        // access token has a narrower scope.
        if (authorizedScopes.contains(OidcScopes.OPENID)) {
            tokenContext = tokenContextBuilder
                    .tokenType(ID_TOKEN_TOKEN_TYPE)
                    .authorization(authorizationBuilder.build())
                    .build();
            OAuth2Token generatedIdToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedIdToken instanceof Jwt jwt)) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(
                                OAuth2ErrorCodes.SERVER_ERROR,
                                "The token generator failed to generate the ID token.",
                                ERROR_URI));
            }
            idToken = new OidcIdToken(
                    jwt.getTokenValue(),
                    jwt.getIssuedAt(),
                    jwt.getExpiresAt(),
                    jwt.getClaims());
            authorizationBuilder.token(
                    idToken,
                    metadata -> metadata.put(
                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            jwt.getClaims()));
        }
        this.authorizationService.save(authorizationBuilder.build());

        return new TokenIssuanceResult(
                registeredClient,
                clientPrincipal,
                accessToken,
                currentRefreshToken,
                idToken != null
                        ? Map.of(OidcParameterNames.ID_TOKEN, idToken.getTokenValue())
                        : Map.of());
    }
}
