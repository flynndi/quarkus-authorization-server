package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcPrompt;
import io.quarkiverse.authorization.server.runtime.util.Arguments;

/** Default validator for redirect URI and scope parameters in an Authorization Code request. */
public final class AuthorizationRequestChecks implements AuthorizationRequestValidator {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    public static final Consumer<AuthorizationRequestContext> DEFAULT_SCOPE_VALIDATOR = AuthorizationRequestChecks::validateScope;
    public static final Consumer<AuthorizationRequestContext> DEFAULT_REDIRECT_URI_VALIDATOR = AuthorizationRequestChecks::validateRedirectUri;

    private final Consumer<AuthorizationRequestContext> authenticationValidator = DEFAULT_REDIRECT_URI_VALIDATOR
            .andThen(DEFAULT_SCOPE_VALIDATOR);

    @Override
    public void validate(AuthorizationRequestContext authenticationContext) {
        this.authenticationValidator.accept(authenticationContext);
        var request = authenticationContext.getRequest();
        var parameters = request.getAdditionalParameters();
        if (request.getScopes().contains(OidcScopes.OPENID) && parameters.containsKey(OidcParameterNames.PROMPT)) {
            Object value = parameters.get(OidcParameterNames.PROMPT);
            if (!(value instanceof String prompt) || !prompt.matches("[\\x21-\\x7E]+(?: [\\x21-\\x7E]+)*")
                    || (request.getPromptValues().contains(OidcPrompt.NONE) && request.getPromptValues().size() != 1)) {
                AuthorizationRequestChecks.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OidcParameterNames.PROMPT,
                        request, authenticationContext.getRegisteredClient());
            }
        }
        if (parameters.containsKey(OAuth2ParameterNames.DPOP_JKT)
                && (!(parameters.get(OAuth2ParameterNames.DPOP_JKT) instanceof String jkt)
                        || !jkt.matches("[A-Za-z0-9_-]{43}")))
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.DPOP_JKT,
                    request,
                    authenticationContext.getRegisteredClient());
    }

    private static void validateScope(AuthorizationRequestContext authenticationContext) {
        AuthorizationRequest authentication = authenticationContext.getRequest();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        Set<String> requestedScopes = authentication.getScopes();
        if (!requestedScopes.isEmpty()
                && !registeredClient.getScopes().containsAll(requestedScopes)) {
            throwError(
                    OAuth2ErrorCodes.INVALID_SCOPE,
                    OAuth2ParameterNames.SCOPE,
                    authentication,
                    registeredClient);
        }
    }

    private static void validateRedirectUri(AuthorizationRequestContext authenticationContext) {
        AuthorizationRequest authentication = authenticationContext.getRequest();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        String requestedRedirectUri = authentication.getRedirectUri();

        if (Arguments.hasText(requestedRedirectUri)) {
            URI requestedRedirect;
            try {
                requestedRedirect = new URI(requestedRedirectUri);
            } catch (URISyntaxException exception) {
                throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ParameterNames.REDIRECT_URI,
                        authentication,
                        registeredClient);
                return;
            }
            if (requestedRedirect.getFragment() != null) {
                throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ParameterNames.REDIRECT_URI,
                        authentication,
                        registeredClient);
            }

            boolean validRedirectUri = isLoopbackAddress(requestedRedirect.getHost())
                    ? registeredClient.getRedirectUris().stream()
                            .anyMatch(
                                    registeredRedirectUri -> matchesLoopbackRedirectUri(
                                            requestedRedirect,
                                            registeredRedirectUri))
                    : registeredClient.getRedirectUris().contains(requestedRedirectUri);
            if (!validRedirectUri) {
                throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ParameterNames.REDIRECT_URI,
                        authentication,
                        registeredClient);
            }
        } else if (authentication.getScopes().contains(OidcScopes.OPENID)
                || registeredClient.getRedirectUris().size() != 1) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.REDIRECT_URI,
                    authentication,
                    registeredClient);
        }
    }

    private static boolean matchesLoopbackRedirectUri(
            URI requestedRedirect, String registeredRedirectUri) {
        URI registeredRedirect;
        try {
            registeredRedirect = new URI(registeredRedirectUri);
        } catch (URISyntaxException exception) {
            return false;
        }
        return isLoopbackAddress(registeredRedirect.getHost())
                && Objects.equals(registeredRedirect.getScheme(), requestedRedirect.getScheme())
                && Objects.equals(
                        registeredRedirect.getRawUserInfo(), requestedRedirect.getRawUserInfo())
                && Objects.equals(registeredRedirect.getHost(), requestedRedirect.getHost())
                && Objects.equals(registeredRedirect.getRawPath(), requestedRedirect.getRawPath())
                && Objects.equals(
                        registeredRedirect.getRawQuery(), requestedRedirect.getRawQuery());
    }

    private static boolean isLoopbackAddress(String host) {
        if (!Arguments.hasText(host)) {
            return false;
        }
        if ("[0:0:0:0:0:0:0:1]".equals(host)
                || "[::1]".equals(host)
                || "0:0:0:0:0:0:0:1".equals(host)
                || "::1".equals(host)) {
            return true;
        }
        String[] octets = host.split("\\.");
        if (octets.length != 4) {
            return false;
        }
        try {
            int first = Integer.parseInt(octets[0]);
            int second = Integer.parseInt(octets[1]);
            int third = Integer.parseInt(octets[2]);
            int fourth = Integer.parseInt(octets[3]);
            return first == 127
                    && second >= 0
                    && second <= 255
                    && third >= 0
                    && third <= 255
                    && fourth >= 1
                    && fourth <= 255;
        } catch (NumberFormatException exception) {
            return false;
        }
    }

    private static void throwError(
            String errorCode,
            String parameterName,
            AuthorizationRequest authentication,
            RegisteredClient registeredClient) {
        String redirectUri = Arguments.hasText(authentication.getRedirectUri())
                ? authentication.getRedirectUri()
                : registeredClient.getRedirectUris().stream().findFirst().orElse(null);
        if (OAuth2ErrorCodes.INVALID_REQUEST.equals(errorCode)
                && OAuth2ParameterNames.REDIRECT_URI.equals(parameterName)) {
            redirectUri = null;
        }

        throw new AuthorizationRequestException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI),
                redirectUri == null
                        ? null
                        : new AuthorizationRedirect(redirectUri, authentication.getState()));
    }
}
