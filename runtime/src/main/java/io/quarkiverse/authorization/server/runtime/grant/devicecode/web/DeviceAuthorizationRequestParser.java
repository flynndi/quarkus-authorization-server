package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceAuthorizationRequest;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Parses Device Authorization parameters and the authenticated client identity. */
public final class DeviceAuthorizationRequestParser {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc8628#section-3.1";

    public DeviceAuthorizationRequest parse(RoutingContext context) {
        SecurityIdentity clientPrincipal = context.user() instanceof QuarkusHttpUser user ? user.getSecurityIdentity() : null;
        if (clientPrincipal == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        MultiMap parameters = context.request().formAttributes();
        String scope = parameters.get(OAuth2ParameterNames.SCOPE);
        if (Arguments.hasText(scope) && parameters.getAll(OAuth2ParameterNames.SCOPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
        }
        Set<String> requestedScopes = Collections.emptySet();
        if (Arguments.hasText(scope)) {
            requestedScopes = new LinkedHashSet<>(Arrays.asList(scope.split(" ")));
        }

        Map<String, Object> additionalParameters = new LinkedHashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new DeviceAuthorizationRequest(
                clientPrincipal, requestedScopes, additionalParameters);
    }

    private static void throwError(String errorCode, String parameterName) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI));
    }
}
