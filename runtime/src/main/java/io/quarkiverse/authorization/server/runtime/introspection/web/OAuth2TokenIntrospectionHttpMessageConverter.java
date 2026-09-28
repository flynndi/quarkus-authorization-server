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
package io.quarkiverse.authorization.server.runtime.introspection.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.authorization.OAuth2TokenIntrospection;
import io.quarkiverse.authorization.server.authorization.OAuth2TokenIntrospectionClaimNames;
import io.quarkiverse.authorization.server.runtime.http.converter.AbstractOAuth2HttpMessageConverter;
import io.vertx.core.http.HttpServerResponse;

/**
 * Writes an OAuth 2.0 Token Introspection Response as JSON.
 */
@Singleton
public final class OAuth2TokenIntrospectionHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OAuth2TokenIntrospectionHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(OAuth2TokenIntrospection tokenIntrospection, HttpServerResponse response) {
        Map<String, Object> responseClaims = new LinkedHashMap<>(tokenIntrospection.getClaims());
        List<String> scopes = tokenIntrospection.getScopes();
        if (scopes != null && !scopes.isEmpty()) {
            responseClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, String.join(" ", scopes));
        }
        if (tokenIntrospection.getExpiresAt() != null) {
            responseClaims.put(OAuth2TokenIntrospectionClaimNames.EXP,
                    tokenIntrospection.getExpiresAt().getEpochSecond());
        }
        if (tokenIntrospection.getIssuedAt() != null) {
            responseClaims.put(OAuth2TokenIntrospectionClaimNames.IAT,
                    tokenIntrospection.getIssuedAt().getEpochSecond());
        }
        if (tokenIntrospection.getNotBefore() != null) {
            responseClaims.put(OAuth2TokenIntrospectionClaimNames.NBF,
                    tokenIntrospection.getNotBefore().getEpochSecond());
        }
        writeJson(responseClaims, response);
    }
}
