package io.quarkiverse.authorization.server.runtime.grant.password;

import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.grant.password.PasswordGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
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
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Validates the Password grant client and issues tokens for an authenticated resource owner. */
@Singleton
public final class PasswordGrant {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext authorizationServerContext;
    private final OAuth2AuthorizationService authorizationService;

    @Inject
    public PasswordGrant(
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            AuthorizationServerContext authorizationServerContext,
            OAuth2AuthorizationService authorizationService) {
        this.tokenGenerator = tokenGenerator;
        this.authorizationServerContext = authorizationServerContext;
        this.authorizationService = authorizationService;
    }

    /**
     * Synchronous issuance after user authentication; the GrantHandler supplies worker execution
     * and request scope.
     */
    public TokenIssuanceResult issueTokens(
            PasswordGrantRequest request, SecurityIdentity resourceOwnerPrincipal) {
        RegisteredClient registeredClient = validateClient(request);
        SecurityIdentity clientPrincipal = request.getClientPrincipal();
        if (resourceOwnerPrincipal.isAnonymous()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        Set<String> authorizedScopes = registeredClient.getScopes();
        if (!request.getScopes().isEmpty()) {
            if (!registeredClient.getScopes().containsAll(request.getScopes())) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
            authorizedScopes = request.getScopes();
        }
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(resourceOwnerPrincipal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(request);
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate the access token.",
                            ERROR_URI));
        }
        OAuth2Authorization.Builder authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(resourceOwnerPrincipal.getPrincipal().getName())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(authorizedScopes)
                .attribute(
                        SecurityIdentity.class.getName(),
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(
                                        new QuarkusPrincipal(
                                                resourceOwnerPrincipal
                                                        .getPrincipal()
                                                        .getName()))
                                .addRoles(resourceOwnerPrincipal.getRoles())
                                .build());
        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(
                authorization, generatedAccessToken, tokenContext);

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(
                                OAuth2ErrorCodes.SERVER_ERROR,
                                "The token generator failed to generate the refresh token.",
                                ERROR_URI));
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorization.refreshToken(refreshToken);
        }

        OidcIdToken idToken = null;
        if (authorizedScopes.contains(OidcScopes.OPENID)) {
            // ID token customizers may need the access token and refresh token from this grant.
            tokenContext = tokenContextBuilder
                    .tokenType(ID_TOKEN_TOKEN_TYPE)
                    .authorization(authorization.build())
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
            authorization.token(
                    idToken,
                    metadata -> metadata.put(
                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            jwt.getClaims()));
        }
        this.authorizationService.save(authorization.build());
        return new TokenIssuanceResult(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                idToken != null
                        ? Map.of(OidcParameterNames.ID_TOKEN, idToken.getTokenValue())
                        : Map.of());
    }

    public RegisteredClient validateClient(PasswordGrantRequest request) {
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(
                request.getClientPrincipal());
        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        return registeredClient;
    }
}
