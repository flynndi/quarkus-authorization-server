package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange;

import java.util.Map;
import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
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
import io.quarkiverse.authorization.server.runtime.util.Arguments;
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

/** Authenticates the OAuth 2.0 Authorization Code Grant and issues an access token. */
@Singleton
public final class AuthorizationCodeExchange {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext authorizationServerContext;
    private final DPoPTokenBinding dpop;

    @Inject
    public AuthorizationCodeExchange(
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
    public TokenIssuanceResult exchange(AuthorizationCodeExchangeRequest authentication) {
        return exchange(authentication, null);
    }

    public TokenIssuanceResult exchange(
            AuthorizationCodeExchangeRequest authentication, DPoPProofRequest proofRequest) {
        SecurityIdentity clientPrincipal = authentication.getClientPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        if (clientPrincipal.isAnonymous() || registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                authentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getAuthorizationCode();
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());

        // All client authentication methods use the same grant-level PKCE check. It runs
        // before any code/replay invalidation or DPoP replay registration can mutate state.
        PkceVerifier.verify(authentication, registeredClient, authorizationRequest);

        if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
            if (!authorizationCode.isInvalidated()) {
                authorization = OAuth2Authorization.from(authorization)
                        .invalidate(authorizationCode.getToken())
                        .build();
                this.authorizationService.save(authorization);
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (Arguments.hasText(authorizationRequest.getRedirectUri())
                && !authorizationRequest.getRedirectUri().equals(authentication.getRedirectUri())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        String codeJkt = (String) authorizationRequest
                .getAdditionalParameters()
                .get(OAuth2ParameterNames.DPOP_JKT);
        DPoPProof proof = this.dpop.verify(proofRequest, codeJkt);
        if (!authorizationCode.isActive()) {
            OAuth2Authorization.Token<? extends OAuth2Token> token = authorization.getRefreshToken() != null
                    ? authorization.getRefreshToken()
                    : authorization.getAccessToken();
            if (authorizationCode.isInvalidated() && token != null) {
                authorization = OAuth2Authorization.from(authorization)
                        .invalidate(token.getToken())
                        .build();
                this.authorizationService.save(authorization);
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        this.dpop.claim(proofRequest, proof);
        SecurityIdentity principal = authorization.getAttribute(SecurityIdentity.class.getName());
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorization(authorization)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authentication);

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

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error(
                                    OAuth2ErrorCodes.SERVER_ERROR,
                                    "The token generator failed to generate a valid refresh token.",
                                    ERROR_URI));
                }
                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                DPoPTokenBinding.bindRefreshToken(
                        authorizationBuilder, refreshToken, clientPrincipal, proof);
            }
        }
        OidcIdToken idToken = null;
        if (authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
            // The ID Token customizer must see the access/refresh tokens issued in this exchange.
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

        authorizationBuilder.invalidate(authorizationCode.getToken());
        this.authorizationService.save(authorizationBuilder.build());

        return new TokenIssuanceResult(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                idToken != null
                        ? Map.of(OidcParameterNames.ID_TOKEN, idToken.getTokenValue())
                        : Map.of());
    }
}
