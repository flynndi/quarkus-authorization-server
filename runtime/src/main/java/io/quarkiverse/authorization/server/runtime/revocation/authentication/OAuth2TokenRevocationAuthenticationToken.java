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
package io.quarkiverse.authorization.server.runtime.revocation.authentication;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * An authentication representation used for OAuth 2.0 Token Revocation.
 */
public final class OAuth2TokenRevocationAuthenticationToken implements Serializable {

    @Serial
    private static final long serialVersionUID = -6946233094369979036L;

    private final String token;
    private final SecurityIdentity clientPrincipal;
    private final String tokenTypeHint;
    private final boolean authenticated;

    public OAuth2TokenRevocationAuthenticationToken(String token, SecurityIdentity clientPrincipal,
            String tokenTypeHint) {
        this.token = Arguments.requireNonBlank(token, "token");
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.tokenTypeHint = tokenTypeHint;
        this.authenticated = false;
    }

    public OAuth2TokenRevocationAuthenticationToken(OAuth2Token revokedToken,
            SecurityIdentity clientPrincipal) {
        Objects.requireNonNull(revokedToken, "revokedToken cannot be null");
        this.token = revokedToken.getTokenValue();
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.tokenTypeHint = null;
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

    public boolean isAuthenticated() {
        return this.authenticated;
    }
}
