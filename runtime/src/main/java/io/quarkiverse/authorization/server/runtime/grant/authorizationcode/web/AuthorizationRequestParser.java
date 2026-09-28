package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.endpoint.PkceParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestException;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Converts an Authorization Request into an {@link AuthorizationRequest}. */
public final class AuthorizationRequestParser {

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
    private static final SecurityIdentity ANONYMOUS_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("anonymousUser"))
            .setAnonymous(true)
            .build();

    public AuthorizationRequest parse(RoutingContext context) {
        return this.parse(context, false);
    }

    public AuthorizationRequest parsePushed(RoutingContext context) {
        return this.parse(context, true);
    }

    private AuthorizationRequest parse(RoutingContext context, boolean pushed) {
        HttpMethod method = context.request().method();
        if (method != HttpMethod.GET && method != HttpMethod.POST) {
            return null;
        }

        MultiMap parameters = method == HttpMethod.GET
                ? context.queryParams()
                : context.request().formAttributes();
        if (parameters.contains(OAuth2ParameterNames.REQUEST_URI)) {
            if (pushed || parameters.getAll(OAuth2ParameterNames.REQUEST_URI).size() != 1
                    || !Arguments.hasText(parameters.get(OAuth2ParameterNames.REQUEST_URI))) {
                AuthorizationRequestParser.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REQUEST_URI);
            }
            String clientId = parameters.get(OAuth2ParameterNames.CLIENT_ID);
            if (!Arguments.hasText(clientId) || parameters.getAll(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
                AuthorizationRequestParser.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
            }
            // The stored request is authoritative. Outer parameters cannot alter scope, state or redirect.
            return new AuthorizationRequest(AuthorizationRequestParser.authorizationUri(context), clientId,
                    context.user() instanceof QuarkusHttpUser user ? user.getSecurityIdentity() : ANONYMOUS_PRINCIPAL,
                    null, null, Set.of(),
                    Map.of(OAuth2ParameterNames.REQUEST_URI, parameters.get(OAuth2ParameterNames.REQUEST_URI)));
        }
        if (pushed && parameters.contains("request")) {
            // JWT-secured authorization request objects are a separate, unsupported capability.
            AuthorizationRequestParser.throwError(OAuth2ErrorCodes.INVALID_REQUEST, "request");
        }
        if (!pushed && method == HttpMethod.POST
                && (parameters.get(OAuth2ParameterNames.RESPONSE_TYPE) == null
                        || !Arguments.hasText(parameters.get(OAuth2ParameterNames.SCOPE))
                        || !Arrays.asList(parameters.get(OAuth2ParameterNames.SCOPE).split(" "))
                                .contains(OidcScopes.OPENID))) {
            return null;
        }

        String responseType = parameters.get(OAuth2ParameterNames.RESPONSE_TYPE);
        if (!Arguments.hasText(responseType)
                || parameters.getAll(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
        } else if (!OAuth2AuthorizationResponseType.CODE.getValue().equals(responseType)) {
            throwError(
                    OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
        }

        String clientId = parameters.get(OAuth2ParameterNames.CLIENT_ID);
        if (!Arguments.hasText(clientId) || parameters.getAll(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
        }

        SecurityIdentity principal = context.user() instanceof QuarkusHttpUser user
                ? user.getSecurityIdentity()
                : ANONYMOUS_PRINCIPAL;

        String redirectUri = parameters.get(OAuth2ParameterNames.REDIRECT_URI);
        if (parameters.getAll(OAuth2ParameterNames.REDIRECT_URI).size() > 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
        }

        Set<String> scopes = Collections.emptySet();
        String scope = parameters.get(OAuth2ParameterNames.SCOPE);
        if (parameters.getAll(OAuth2ParameterNames.SCOPE).size() > 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
        }
        if (Arguments.hasText(scope)) {
            scopes = new LinkedHashSet<>(Arrays.asList(scope.split(" ")));
        }

        String state = parameters.get(OAuth2ParameterNames.STATE);
        if (parameters.getAll(OAuth2ParameterNames.STATE).size() > 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        if (parameters.getAll(PkceParameterNames.CODE_CHALLENGE).size() > 1) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    PkceParameterNames.CODE_CHALLENGE,
                    PKCE_ERROR_URI);
        }

        if (parameters.getAll(PkceParameterNames.CODE_CHALLENGE_METHOD).size() > 1) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    PkceParameterNames.CODE_CHALLENGE_METHOD,
                    PKCE_ERROR_URI);
        }

        if (parameters.contains(OidcParameterNames.NONCE)
                && (parameters.getAll(OidcParameterNames.NONCE).size() != 1
                        || !Arguments.hasText(parameters.get(OidcParameterNames.NONCE)))) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OidcParameterNames.NONCE);
        }

        if (parameters.getAll(OidcParameterNames.PROMPT).size() > 1) {
            AuthorizationRequestParser.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OidcParameterNames.PROMPT);
        }

        Map<String, Object> additionalParameters = new LinkedHashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.RESPONSE_TYPE.equals(parameterName)
                    && !OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                    && !OAuth2ParameterNames.REDIRECT_URI.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)
                    && !OAuth2ParameterNames.STATE.equals(parameterName)
                    && !(pushed && Set.of(OAuth2ParameterNames.CLIENT_SECRET, OAuth2ParameterNames.CLIENT_ASSERTION,
                            OAuth2ParameterNames.CLIENT_ASSERTION_TYPE).contains(parameterName))) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new AuthorizationRequest(
                authorizationUri(context),
                clientId,
                principal,
                redirectUri,
                state,
                scopes,
                additionalParameters);
    }

    private static String authorizationUri(RoutingContext context) {
        String absoluteUri = context.request().absoluteURI();
        int queryIndex = absoluteUri.indexOf('?');
        return queryIndex >= 0 ? absoluteUri.substring(0, queryIndex) : absoluteUri;
    }

    private static void throwError(String errorCode, String parameterName) {
        throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
    }

    private static void throwError(String errorCode, String parameterName, String errorUri) {
        throw new AuthorizationRequestException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri),
                null);
    }
}
