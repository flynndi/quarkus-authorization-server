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
package io.quarkiverse.authorization.server.grant.clientcredentials;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol input for the OAuth 2.0 Client Credentials Grant. */
public final class ClientCredentialsRequest extends TokenGrantRequest {

    private final Set<String> scopes;

    public ClientCredentialsRequest(
            SecurityIdentity clientPrincipal,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.CLIENT_CREDENTIALS, clientPrincipal, additionalParameters);
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
