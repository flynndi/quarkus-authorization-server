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
package io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/** Converts a Token Exchange request into an {@link TokenExchangeRequest}. */
public final class TokenExchangeRequestParser {

    static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";
    static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

    private static final String TOKEN_TYPE_IDENTIFIERS_URI = "https://datatracker.ietf.org/doc/html/rfc8693#section-3";
    private static final Set<String> SUPPORTED_TOKEN_TYPES = Set.of(ACCESS_TOKEN_TYPE_VALUE, JWT_TOKEN_TYPE_VALUE);

    public TokenExchangeRequest parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        String grantType = parameters.get(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.TOKEN_EXCHANGE.getValue().equals(grantType)) {
            return null;
        }

        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        SecurityIdentity clientPrincipal = user.getSecurityIdentity();

        List<String> resources = parameters.getAll(OAuth2ParameterNames.RESOURCE);
        for (String resource : resources) {
            if (!isValidUri(resource)) {
                OAuth2EndpointUtils.throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        OAuth2ParameterNames.RESOURCE,
                        OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
            }
        }

        List<String> audiences = parameters.getAll(OAuth2ParameterNames.AUDIENCE);

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

        String requestedTokenType = parameters.get(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE);
        if (Arguments.hasText(requestedTokenType)) {
            requireSingleValue(parameters, OAuth2ParameterNames.REQUESTED_TOKEN_TYPE);
            validateTokenType(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, requestedTokenType);
        } else {
            requestedTokenType = ACCESS_TOKEN_TYPE_VALUE;
        }

        String subjectToken = parameters.get(OAuth2ParameterNames.SUBJECT_TOKEN);
        if (!Arguments.hasText(subjectToken)
                || parameters.getAll(OAuth2ParameterNames.SUBJECT_TOKEN).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.SUBJECT_TOKEN,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        String subjectTokenType = parameters.get(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE);
        if (!Arguments.hasText(subjectTokenType)
                || parameters.getAll(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.SUBJECT_TOKEN_TYPE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        validateTokenType(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, subjectTokenType);

        String actorToken = parameters.get(OAuth2ParameterNames.ACTOR_TOKEN);
        if (Arguments.hasText(actorToken)
                && parameters.getAll(OAuth2ParameterNames.ACTOR_TOKEN).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.ACTOR_TOKEN,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        String actorTokenType = parameters.get(OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
        if (Arguments.hasText(actorTokenType)) {
            requireSingleValue(parameters, OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
            validateTokenType(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, actorTokenType);
        }

        if (!Arguments.hasText(actorToken) && Arguments.hasText(actorTokenType)) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.ACTOR_TOKEN,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        } else if (Arguments.hasText(actorToken) && !Arguments.hasText(actorTokenType)) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.ACTOR_TOKEN_TYPE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        for (String parameterName : parameters.names()) {
            if (!Set.of(
                    OAuth2ParameterNames.GRANT_TYPE,
                    OAuth2ParameterNames.RESOURCE,
                    OAuth2ParameterNames.AUDIENCE,
                    OAuth2ParameterNames.REQUESTED_TOKEN_TYPE,
                    OAuth2ParameterNames.SUBJECT_TOKEN,
                    OAuth2ParameterNames.SUBJECT_TOKEN_TYPE,
                    OAuth2ParameterNames.ACTOR_TOKEN,
                    OAuth2ParameterNames.ACTOR_TOKEN_TYPE,
                    OAuth2ParameterNames.SCOPE)
                    .contains(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new TokenExchangeRequest(
                resources,
                audiences,
                requestedScopes,
                requestedTokenType,
                subjectToken,
                subjectTokenType,
                actorToken,
                actorTokenType,
                clientPrincipal,
                additionalParameters);
    }

    private static void requireSingleValue(MultiMap parameters, String parameterName) {
        if (parameters.getAll(parameterName).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    parameterName,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
    }

    private static void validateTokenType(String parameterName, String tokenTypeValue) {
        if (!SUPPORTED_TOKEN_TYPES.contains(tokenTypeValue)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE,
                            "OAuth 2.0 Token Exchange parameter: " + parameterName,
                            TOKEN_TYPE_IDENTIFIERS_URI));
        }
    }

    private static boolean isValidUri(String value) {
        try {
            URI uri = new URI(value);
            return uri.isAbsolute() && uri.getFragment() == null;
        } catch (URISyntaxException exception) {
            return false;
        }
    }
}
