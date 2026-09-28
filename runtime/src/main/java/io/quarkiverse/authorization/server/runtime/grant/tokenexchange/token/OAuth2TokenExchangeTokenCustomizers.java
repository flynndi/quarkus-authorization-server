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
package io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.jwt.Claims;

import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkus.security.identity.SecurityIdentity;

/** Built-in claim customization for the Token Exchange grant. */
public final class OAuth2TokenExchangeTokenCustomizers {

    /** Identity attribute containing actor claim maps, ordered from current to oldest actor. */
    public static final String ACTORS_ATTRIBUTE = "oauth2.token-exchange.actors";

    /** Reads and freezes the protocol attribute without depending on a SecurityIdentity subtype. */
    public static List<Map<String, Object>> getActors(SecurityIdentity identity) {
        return getActors(identity == null ? Map.of() : identity.getAttributes());
    }

    /** The same protocol contract for Jackson's already-bound identity attributes. */
    public static List<Map<String, Object>> getActors(Map<String, Object> attributes) {
        Object value = attributes.get(ACTORS_ATTRIBUTE);
        if (value == null && !attributes.containsKey(ACTORS_ATTRIBUTE))
            return List.of();
        if (!(value instanceof List<?> values)) {
            throw new IllegalArgumentException(
                    "Token exchange actors must be a list of claim maps");
        }
        List<Map<String, Object>> actors = new ArrayList<>();
        for (Object actor : values) {
            if (!(actor instanceof Map<?, ?> claims)
                    || !(claims.get(Claims.sub.name()) instanceof String subject)
                    || subject.isBlank()
                    || (claims.containsKey(Claims.iss.name())
                            && (!(claims.get(Claims.iss.name()) instanceof String issuer)
                                    || issuer.isBlank()))) {
                throw new IllegalArgumentException(
                        "Token exchange actors require valid sub and optional iss claims");
            }
            Map<String, Object> copy = new LinkedHashMap<>();
            claims.forEach(
                    (key, claim) -> {
                        if (!(key instanceof String name) || claim == null) {
                            throw new IllegalArgumentException(
                                    "Invalid token exchange actor claim");
                        }
                        copy.put(name, claim);
                    });
            actors.add(Collections.unmodifiableMap(copy));
        }
        return List.copyOf(actors);
    }

    private OAuth2TokenExchangeTokenCustomizers() {
    }

    public static OAuth2TokenCustomizer<JwtEncodingContext> jwt() {
        return context -> context.getClaims().claims(claims -> customize(context, claims));
    }

    public static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessToken() {
        return context -> context.getClaims().claims(claims -> customize(context, claims));
    }

    private static void customize(OAuth2TokenContext context, Map<String, Object> claims) {
        if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
            return;
        }

        if (context.getAuthorizationGrant() instanceof TokenExchangeRequest authentication) {
            List<String> audience = authentication.getAudiences();
            if (!audience.isEmpty()) {
                claims.put(Claims.aud.name(), audience);
            }
        }

        if (context.getPrincipal() != null) {
            Map<String, Object> currentClaims = claims;
            for (Map<String, Object> actor : getActors(context.getPrincipal())) {
                Map<String, Object> actClaim = new HashMap<>();
                actClaim.put(Claims.sub.name(), actor.get(Claims.sub.name()));
                if (actor.containsKey(Claims.iss.name()))
                    actClaim.put(Claims.iss.name(), actor.get(Claims.iss.name()));
                currentClaims.put("act", Collections.unmodifiableMap(actClaim));
                currentClaims = actClaim;
            }
        }
    }
}
