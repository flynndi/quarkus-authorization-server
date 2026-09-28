package io.quarkiverse.authorization.server.runtime.grant.password.web;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.password.PasswordGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Converts a password grant token request into an {@link PasswordGrantRequest}. */
public final class PasswordGrantRequestParser {

    public PasswordGrantRequest parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        String grantType = parameters.get(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }
        if (parameters.getAll(OAuth2ParameterNames.GRANT_TYPE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.GRANT_TYPE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        SecurityIdentity clientPrincipal = user.getSecurityIdentity();

        List<String> scopeValues = parameters.getAll(OAuth2ParameterNames.SCOPE);
        if (scopeValues.size() > 1 || (scopeValues.size() == 1 && scopeValues.get(0).isBlank())) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.SCOPE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = Collections.emptySet();
        if (scopeValues.size() == 1) {
            String[] scopes = scopeValues.get(0).split(" ", -1);
            if (Arrays.stream(scopes).anyMatch(String::isBlank)) {
                OAuth2EndpointUtils.throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ParameterNames.SCOPE,
                        OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
            }
            requestedScopes = new HashSet<>(Arrays.asList(scopes));
        }

        List<String> usernameValues = parameters.getAll(OAuth2ParameterNames.USERNAME);
        if (usernameValues.size() != 1 || usernameValues.get(0).isBlank()) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.USERNAME,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        String username = usernameValues.get(0);

        List<String> passwordValues = parameters.getAll(OAuth2ParameterNames.PASSWORD);
        if (passwordValues.size() != 1 || passwordValues.get(0).isBlank()) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.PASSWORD,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        String password = passwordValues.get(0);

        Map<String, Object> additionalParameters = new HashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.GRANT_TYPE.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)
                    && !OAuth2ParameterNames.USERNAME.equals(parameterName)
                    && !OAuth2ParameterNames.PASSWORD.equals(parameterName)) {
                additionalParameters.put(parameterName, parameters.get(parameterName));
            }
        }

        return new PasswordGrantRequest(
                clientPrincipal, username, password, additionalParameters, requestedScopes);
    }
}
