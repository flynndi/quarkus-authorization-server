package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceAuthorizationRequest;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeGenerator;
import io.quarkiverse.authorization.server.grant.devicecode.UserCodeGenerator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.security.identity.SecurityIdentity;

/** Validates a Device Authorization Request and issues its device and user codes. */
@Singleton
public final class DeviceAuthorizationService {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);
    static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.USER_CODE);

    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationServerContext authorizationServerContext;
    private final DeviceCodeGenerator deviceCodeGenerator;
    private final UserCodeGenerator userCodeGenerator;

    @Inject
    public DeviceAuthorizationService(
            OAuth2AuthorizationService authorizationService,
            AuthorizationServerContext authorizationServerContext,
            DeviceCodeGenerator deviceCodeGenerator,
            UserCodeGenerator userCodeGenerator) {

        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.authorizationServerContext = Objects.requireNonNull(
                authorizationServerContext, "authorizationServerContext cannot be null");
        this.deviceCodeGenerator = Objects.requireNonNull(deviceCodeGenerator, "deviceCodeGenerator cannot be null");
        this.userCodeGenerator = Objects.requireNonNull(userCodeGenerator, "userCodeGenerator cannot be null");
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public DeviceCodesIssued authorize(DeviceAuthorizationRequest request) {
        Objects.requireNonNull(request, "request cannot be null");
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils.getIdentifiedClientElseThrowInvalidClient(
                request.getClientPrincipal());

        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.DEVICE_CODE)) {
            throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID);
        }

        Set<String> requestedScopes = request.getScopes();
        for (String requestedScope : requestedScopes) {
            if (!registeredClient.getScopes().contains(requestedScope)) {
                throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE);
            }
        }

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrant(request);

        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(DEVICE_CODE_TOKEN_TYPE).build();
        OAuth2DeviceCode deviceCode = this.deviceCodeGenerator.generate(tokenContext);
        if (deviceCode == null) {
            throw tokenGenerationFailed("device code");
        }

        tokenContext = tokenContextBuilder.tokenType(USER_CODE_TOKEN_TYPE).build();
        OAuth2UserCode userCode = this.userCodeGenerator.generate(tokenContext);
        if (userCode == null) {
            throw tokenGenerationFailed("user code");
        }

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getPrincipal().getName())
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .token(deviceCode)
                .token(userCode)
                .attribute(OAuth2ParameterNames.SCOPE, new HashSet<>(requestedScopes))
                .build();
        this.authorizationService.save(authorization);

        return new DeviceCodesIssued(deviceCode, userCode);
    }

    private static void throwError(String errorCode, String parameterName) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI));
    }

    private static OAuth2AuthenticationException tokenGenerationFailed(String tokenName) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the " + tokenName + ".",
                        ERROR_URI));
    }
}
