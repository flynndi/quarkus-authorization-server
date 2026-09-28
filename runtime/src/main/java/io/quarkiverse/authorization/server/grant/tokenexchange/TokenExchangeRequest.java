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
package io.quarkiverse.authorization.server.grant.tokenexchange;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol input for the OAuth 2.0 Token Exchange Grant. */
public final class TokenExchangeRequest extends TokenGrantRequest {

    private final List<String> resources;
    private final List<String> audiences;
    private final String requestedTokenType;
    private final String subjectToken;
    private final String subjectTokenType;
    private final String actorToken;
    private final String actorTokenType;
    private final Set<String> scopes;

    public TokenExchangeRequest(
            List<String> resources,
            List<String> audiences,
            Set<String> scopes,
            String requestedTokenType,
            String subjectToken,
            String subjectTokenType,
            String actorToken,
            String actorTokenType,
            SecurityIdentity clientPrincipal,
            Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.TOKEN_EXCHANGE, clientPrincipal, additionalParameters);
        if (resources == null) {
            throw new IllegalArgumentException("resources cannot be null");
        }
        if (audiences == null) {
            throw new IllegalArgumentException("audiences cannot be null");
        }
        Arguments.requireNonBlank(requestedTokenType, "requestedTokenType");
        Arguments.requireNonBlank(subjectToken, "subjectToken");
        Arguments.requireNonBlank(subjectTokenType, "subjectTokenType");
        this.resources = Collections.unmodifiableList(new ArrayList<>(resources));
        this.audiences = Collections.unmodifiableList(new ArrayList<>(audiences));
        this.requestedTokenType = requestedTokenType;
        this.subjectToken = subjectToken;
        this.subjectTokenType = subjectTokenType;
        this.actorToken = actorToken;
        this.actorTokenType = actorTokenType;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    public List<String> getResources() {
        return this.resources;
    }

    public List<String> getAudiences() {
        return this.audiences;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public String getRequestedTokenType() {
        return this.requestedTokenType;
    }

    public String getSubjectToken() {
        return this.subjectToken;
    }

    public String getSubjectTokenType() {
        return this.subjectTokenType;
    }

    public String getActorToken() {
        return this.actorToken;
    }

    public String getActorTokenType() {
        return this.actorTokenType;
    }
}
