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
package io.quarkiverse.authorization.server.runtime.revocation.web;

import java.util.List;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.web.authentication.AuthenticationConverter;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/**
 * Converts an HTTP Token Revocation Request into its authentication representation.
 */
public final class OAuth2TokenRevocationAuthenticationConverter
        implements AuthenticationConverter<OAuth2TokenRevocationAuthenticationToken> {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7009#section-2.1";

    @Override
    public OAuth2TokenRevocationAuthenticationToken convert(RoutingContext context) {
        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        MultiMap parameters = context.request().formAttributes();
        List<String> tokenValues = parameters.getAll(OAuth2ParameterNames.TOKEN);
        String token = tokenValues.isEmpty() ? null : tokenValues.get(0);
        if (token == null || token.isBlank() || tokenValues.size() != 1) {
            throwError(OAuth2ParameterNames.TOKEN);
        }

        List<String> tokenTypeHintValues = parameters.getAll(OAuth2ParameterNames.TOKEN_TYPE_HINT);
        String tokenTypeHint = tokenTypeHintValues.isEmpty() ? null : tokenTypeHintValues.get(0);
        if (tokenTypeHint != null && !tokenTypeHint.isBlank() && tokenTypeHintValues.size() != 1) {
            throwError(OAuth2ParameterNames.TOKEN_TYPE_HINT);
        }

        return new OAuth2TokenRevocationAuthenticationToken(
                token, user.getSecurityIdentity(), tokenTypeHint);
    }

    private static void throwError(String parameterName) {
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "OAuth 2.0 Token Revocation Parameter: " + parameterName,
                ERROR_URI));
    }
}
