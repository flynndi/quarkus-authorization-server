/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Converts a Client Credentials token request into an {@link ClientCredentialsRequest}. */
public final class ClientCredentialsRequestParser {

    public ClientCredentialsRequest parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        String grantType = parameters.get(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
            return null;
        }

        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        SecurityIdentity clientPrincipal = user.getSecurityIdentity();

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
            requestedScopes = new HashSet<>(Arrays.asList(scope.split(" ", -1)));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.GRANT_TYPE.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new ClientCredentialsRequest(clientPrincipal, requestedScopes, additionalParameters);
    }
}
