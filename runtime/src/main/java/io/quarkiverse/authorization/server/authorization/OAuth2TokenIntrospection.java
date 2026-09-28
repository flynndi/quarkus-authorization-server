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
package io.quarkiverse.authorization.server.authorization;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * A representation of the claims returned in an OAuth 2.0 Token Introspection Response.
 */
public final class OAuth2TokenIntrospection implements OAuth2TokenIntrospectionClaimAccessor, Serializable {

    @Serial
    private static final long serialVersionUID = 7883995789250883004L;

    private final Map<String, Object> claims;

    private OAuth2TokenIntrospection(Map<String, Object> claims) {
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    public static Builder builder() {
        return builder(false);
    }

    public static Builder builder(boolean active) {
        return new Builder(active);
    }

    public static Builder withClaims(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            throw new IllegalArgumentException("claims cannot be empty");
        }
        return builder().claims(values -> values.putAll(claims));
    }

    public static class Builder {

        private final Map<String, Object> claims = new LinkedHashMap<>();

        private Builder(boolean active) {
            active(active);
        }

        public Builder active(boolean active) {
            return claim(OAuth2TokenIntrospectionClaimNames.ACTIVE, active);
        }

        public Builder scope(String scope) {
            addClaimToClaimList(OAuth2TokenIntrospectionClaimNames.SCOPE, scope);
            return this;
        }

        public Builder scopes(Consumer<List<String>> scopesConsumer) {
            acceptClaimValues(OAuth2TokenIntrospectionClaimNames.SCOPE, scopesConsumer);
            return this;
        }

        public Builder clientId(String clientId) {
            return claim(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, clientId);
        }

        public Builder username(String username) {
            return claim(OAuth2TokenIntrospectionClaimNames.USERNAME, username);
        }

        public Builder tokenType(String tokenType) {
            return claim(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE, tokenType);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim(OAuth2TokenIntrospectionClaimNames.EXP, expiresAt);
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim(OAuth2TokenIntrospectionClaimNames.IAT, issuedAt);
        }

        public Builder notBefore(Instant notBefore) {
            return claim(OAuth2TokenIntrospectionClaimNames.NBF, notBefore);
        }

        public Builder subject(String subject) {
            return claim(OAuth2TokenIntrospectionClaimNames.SUB, subject);
        }

        public Builder audience(String audience) {
            addClaimToClaimList(OAuth2TokenIntrospectionClaimNames.AUD, audience);
            return this;
        }

        public Builder audiences(Consumer<List<String>> audiencesConsumer) {
            acceptClaimValues(OAuth2TokenIntrospectionClaimNames.AUD, audiencesConsumer);
            return this;
        }

        public Builder issuer(String issuer) {
            return claim(OAuth2TokenIntrospectionClaimNames.ISS, issuer);
        }

        public Builder id(String id) {
            return claim(OAuth2TokenIntrospectionClaimNames.JTI, id);
        }

        public Builder claim(String name, Object value) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("name cannot be empty");
            }
            this.claims.put(name, Objects.requireNonNull(value, "value cannot be null"));
            return this;
        }

        public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            Objects.requireNonNull(claimsConsumer, "claimsConsumer cannot be null").accept(this.claims);
            return this;
        }

        public OAuth2TokenIntrospection build() {
            validate();
            return new OAuth2TokenIntrospection(this.claims);
        }

        private void validate() {
            requireType(OAuth2TokenIntrospectionClaimNames.ACTIVE, Boolean.class);
            requireOptionalType(OAuth2TokenIntrospectionClaimNames.SCOPE, List.class);
            requireOptionalType(OAuth2TokenIntrospectionClaimNames.EXP, Instant.class);
            requireOptionalType(OAuth2TokenIntrospectionClaimNames.IAT, Instant.class);
            requireOptionalType(OAuth2TokenIntrospectionClaimNames.NBF, Instant.class);
            requireOptionalType(OAuth2TokenIntrospectionClaimNames.AUD, List.class);
            Object issuer = this.claims.get(OAuth2TokenIntrospectionClaimNames.ISS);
            if (issuer != null && !(issuer instanceof URL)) {
                try {
                    new URI(issuer.toString()).toURL();
                } catch (Exception exception) {
                    throw new IllegalArgumentException("iss must be a valid URL", exception);
                }
            }
        }

        private void requireType(String name, Class<?> type) {
            Object value = this.claims.get(name);
            if (!type.isInstance(value)) {
                throw new IllegalArgumentException(name + " must be of type " + type.getSimpleName());
            }
        }

        private void requireOptionalType(String name, Class<?> type) {
            if (this.claims.containsKey(name)) {
                requireType(name, type);
            }
        }

        @SuppressWarnings("unchecked")
        private void addClaimToClaimList(String name, String value) {
            Objects.requireNonNull(value, "value cannot be null");
            this.claims.computeIfAbsent(name, ignored -> new LinkedList<String>());
            ((List<String>) this.claims.get(name)).add(value);
        }

        @SuppressWarnings("unchecked")
        private void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
            Objects.requireNonNull(valuesConsumer, "valuesConsumer cannot be null");
            this.claims.computeIfAbsent(name, ignored -> new LinkedList<String>());
            valuesConsumer.accept((List<String>) this.claims.get(name));
        }
    }
}
