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

import java.util.Objects;

import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Authenticates an OAuth 2.0 Token Revocation request.
 */
public final class OAuth2TokenRevocationAuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;

    @Inject
    public OAuth2TokenRevocationAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = Objects.requireNonNull(
                authorizationService, "authorizationService cannot be null");
    }

    /** Synchronous protocol work; the HTTP entry point supplies worker execution and a CDI request context. */
    public OAuth2TokenRevocationAuthenticationToken authenticate(
            OAuth2TokenRevocationAuthenticationToken authentication) {
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils
                .getAuthenticatedClientElseThrowInvalidClient(authentication.getPrincipal());
        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                authentication.getToken(), null);
        if (authorization == null) {
            return authentication;
        }

        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        OAuth2Authorization.Token<OAuth2Token> token = authorization.getToken(authentication.getToken());
        authorization = OAuth2Authorization.from(authorization).invalidate(token.getToken()).build();
        this.authorizationService.save(authorization);

        return new OAuth2TokenRevocationAuthenticationToken(token.getToken(), clientPrincipal);
    }
}
