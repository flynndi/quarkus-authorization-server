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
package io.quarkiverse.authorization.server.runtime.introspection.authentication;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2TokenIntrospection;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * An authentication representation used for OAuth 2.0 Token Introspection.
 */
public final class OAuth2TokenIntrospectionAuthenticationToken implements Serializable {

    @Serial
    private static final long serialVersionUID = 6283745750333226278L;

    private final String token;
    private final SecurityIdentity clientPrincipal;
    private final String tokenTypeHint;
    private final Map<String, Object> additionalParameters;
    private final OAuth2TokenIntrospection tokenClaims;
    private final boolean authenticated;

    public OAuth2TokenIntrospectionAuthenticationToken(String token, SecurityIdentity clientPrincipal,
            String tokenTypeHint, Map<String, Object> additionalParameters) {
        this.token = Arguments.requireNonBlank(token, "token");
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.tokenTypeHint = tokenTypeHint;
        this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null
                ? new LinkedHashMap<>(additionalParameters)
                : Collections.emptyMap());
        this.tokenClaims = OAuth2TokenIntrospection.builder().build();
        this.authenticated = false;
    }

    public OAuth2TokenIntrospectionAuthenticationToken(String token, SecurityIdentity clientPrincipal,
            OAuth2TokenIntrospection tokenClaims) {
        this.token = Arguments.requireNonBlank(token, "token");
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.tokenTypeHint = null;
        this.additionalParameters = Collections.emptyMap();
        this.tokenClaims = Objects.requireNonNull(tokenClaims, "tokenClaims cannot be null");
        // The introspection request was authenticated even when the presented token is inactive.
        this.authenticated = true;
    }

    public SecurityIdentity getPrincipal() {
        return this.clientPrincipal;
    }

    public Object getCredentials() {
        return "";
    }

    public String getToken() {
        return this.token;
    }

    public String getTokenTypeHint() {
        return this.tokenTypeHint;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public OAuth2TokenIntrospection getTokenClaims() {
        return this.tokenClaims;
    }

    public boolean isAuthenticated() {
        return this.authenticated;
    }
}
