package io.quarkiverse.authorization.server.runtime.grant.devicecode.exchange;

import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;

/** Exchanges an approved device code for tokens. */
@Singleton
public final class DeviceCodeExchange {

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final String DEVICE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5";
    static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);
    static final String EXPIRED_TOKEN = "expired_token";
    static final String AUTHORIZATION_PENDING = "authorization_pending";

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext authorizationServerContext;
    private final DPoPTokenBinding dpop;

    @Inject
    public DeviceCodeExchange(
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
    public TokenIssuanceResult exchange(DeviceCodeExchangeRequest request) {
        return exchange(request, null);
    }

    public TokenIssuanceResult exchange(
            DeviceCodeExchangeRequest request, DPoPProofRequest proofRequest) {
        Objects.requireNonNull(request, "request cannot be null");
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils.getIdentifiedClientElseThrowInvalidClient(
                request.getClientPrincipal());

        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                request.getDeviceCode(), DEVICE_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);
        if (userCode == null || deviceCode == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            if (!deviceCode.isInvalidated()) {
                authorization = OAuth2Authorization.from(authorization)
                        .invalidate(deviceCode.getToken())
                        .build();
                this.authorizationService.save(authorization);
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // RFC 8628 ends an expired device session even when user interaction is still pending.
        if (deviceCode.isExpired()) {
            if (!deviceCode.isInvalidated()) {
                authorization = OAuth2Authorization.from(authorization)
                        .invalidate(deviceCode.getToken())
                        .build();
                this.authorizationService.save(authorization);
            }
            throw deviceError(EXPIRED_TOKEN);
        }
        if (!userCode.isInvalidated()) {
            throw deviceError(AUTHORIZATION_PENDING);
        }
        if (deviceCode.isInvalidated()) {
            throw deviceError(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        SecurityIdentity principal = authorization.getAttribute(SecurityIdentity.class.getName());
        if (principal == null || principal.isAnonymous()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        DPoPProof proof = this.dpop.verify(proofRequest, null);
        this.dpop.claim(proofRequest, proof);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorization(authorization)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrant(request);

        if (proof != null)
            tokenContextBuilder.put(DPoPProof.class, proof);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
                .invalidate(deviceCode.getToken());

        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw tokenGenerationFailed("access token");
        }

        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(
                authorizationBuilder, generatedAccessToken, tokenContext);

        boolean publicClient = ClientAuthenticationMethod.NONE.equals(
                clientPrincipal.getAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE));
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            // An unbound public client can receive an access token, but no refresh token.
            if (generatedRefreshToken != null || !publicClient || proof != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken generated)) {
                    throw tokenGenerationFailed("refresh token");
                }
                refreshToken = generated;
                DPoPTokenBinding.bindRefreshToken(
                        authorizationBuilder, refreshToken, clientPrincipal, proof);
            }
        }

        this.authorizationService.save(authorizationBuilder.build());
        return new TokenIssuanceResult(
                registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    private static OAuth2AuthenticationException deviceError(String errorCode) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, null, DEVICE_ERROR_URI));
    }

    private static OAuth2AuthenticationException tokenGenerationFailed(String tokenName) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the " + tokenName + ".",
                        DEFAULT_ERROR_URI));
    }
}
