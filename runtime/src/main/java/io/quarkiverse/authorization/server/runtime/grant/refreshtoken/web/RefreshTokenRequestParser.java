package io.quarkiverse.authorization.server.runtime.grant.refreshtoken.web;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Converts a Refresh Token token request into an {@link RefreshTokenRequest}. */
public final class RefreshTokenRequestParser {

    public RefreshTokenRequest parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        String grantType = parameters.get(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }

        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        SecurityIdentity clientPrincipal = user.getSecurityIdentity();

        List<String> refreshTokenValues = parameters.getAll(OAuth2ParameterNames.REFRESH_TOKEN);
        if (refreshTokenValues.size() != 1 || refreshTokenValues.get(0).isBlank()) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.REFRESH_TOKEN,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        String refreshToken = refreshTokenValues.get(0);

        List<String> scopeValues = parameters.getAll(OAuth2ParameterNames.SCOPE);
        String scope = scopeValues.isEmpty() ? null : scopeValues.get(0);
        if (Arguments.hasText(scope) && scopeValues.size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.SCOPE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (Arguments.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(scope.split(" ")));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.GRANT_TYPE.equals(parameterName)
                    && !OAuth2ParameterNames.REFRESH_TOKEN.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new RefreshTokenRequest(
                refreshToken, clientPrincipal, requestedScopes, additionalParameters);
    }
}
