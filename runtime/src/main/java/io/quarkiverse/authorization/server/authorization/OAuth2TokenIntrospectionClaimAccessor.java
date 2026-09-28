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

import java.net.URL;
import java.time.Instant;
import java.util.List;

import io.quarkiverse.authorization.server.token.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for an OAuth 2.0 Token Introspection Response.
 */
public interface OAuth2TokenIntrospectionClaimAccessor extends ClaimAccessor {

    default boolean isActive() {
        return Boolean.TRUE.equals(getClaimAsBoolean(OAuth2TokenIntrospectionClaimNames.ACTIVE));
    }

    default String getUsername() {
        return getClaimAsString(OAuth2TokenIntrospectionClaimNames.USERNAME);
    }

    default String getClientId() {
        return getClaimAsString(OAuth2TokenIntrospectionClaimNames.CLIENT_ID);
    }

    default List<String> getScopes() {
        return getClaimAsStringList(OAuth2TokenIntrospectionClaimNames.SCOPE);
    }

    default String getTokenType() {
        return getClaimAsString(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE);
    }

    default Instant getExpiresAt() {
        return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.EXP);
    }

    default Instant getIssuedAt() {
        return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.IAT);
    }

    default Instant getNotBefore() {
        return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.NBF);
    }

    default String getSubject() {
        return getClaimAsString(OAuth2TokenIntrospectionClaimNames.SUB);
    }

    default List<String> getAudience() {
        return getClaimAsStringList(OAuth2TokenIntrospectionClaimNames.AUD);
    }

    default URL getIssuer() {
        return getClaimAsURL(OAuth2TokenIntrospectionClaimNames.ISS);
    }

    default String getId() {
        return getClaimAsString(OAuth2TokenIntrospectionClaimNames.JTI);
    }
}
