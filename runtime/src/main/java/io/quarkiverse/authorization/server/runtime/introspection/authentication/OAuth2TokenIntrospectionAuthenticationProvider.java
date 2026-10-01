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

import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2TokenIntrospection;
import io.quarkiverse.authorization.server.authorization.OAuth2TokenIntrospectionClaimNames;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Authenticates an OAuth 2.0 Token Introspection request.
 */
public final class OAuth2TokenIntrospectionAuthenticationProvider {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    @Inject
    public OAuth2TokenIntrospectionAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService) {
        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationService = Objects.requireNonNull(
                authorizationService, "authorizationService cannot be null");
    }

    /** Synchronous protocol work; the HTTP entry point supplies worker execution and a CDI request context. */
    public OAuth2TokenIntrospectionAuthenticationToken authenticate(
            OAuth2TokenIntrospectionAuthenticationToken authentication) {
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils
                .getAuthenticatedClientElseThrowInvalidClient(authentication.getPrincipal());

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                authentication.getToken(), null);
        // The repository lookup can match consent state without matching a token.
        OAuth2Authorization.Token<OAuth2Token> authorizedToken = authorization != null
                ? authorization.getToken(authentication.getToken())
                : null;
        if (authorizedToken == null) {
            // The unchanged request represents an inactive token with only active=false.
            return authentication;
        }

        if (!authorizedToken.isActive()) {
            return inactive(authentication.getToken(), clientPrincipal);
        }

        RegisteredClient authorizedClient = this.registeredClientRepository.findById(
                authorization.getRegisteredClientId());
        if (authorizedClient == null) {
            throw new IllegalStateException("The registered client associated with the authorization was not found");
        }
        OAuth2TokenIntrospection tokenClaims = withActiveTokenClaims(authorizedToken, authorizedClient);
        return new OAuth2TokenIntrospectionAuthenticationToken(
                authorizedToken.getToken().getTokenValue(), clientPrincipal, tokenClaims);
    }

    private static OAuth2TokenIntrospectionAuthenticationToken inactive(
            String token, SecurityIdentity clientPrincipal) {
        return new OAuth2TokenIntrospectionAuthenticationToken(
                token, clientPrincipal, OAuth2TokenIntrospection.builder().build());
    }

    private static OAuth2TokenIntrospection withActiveTokenClaims(
            OAuth2Authorization.Token<OAuth2Token> authorizedToken, RegisteredClient authorizedClient) {
        OAuth2TokenIntrospection.Builder tokenClaims;
        if (authorizedToken.getClaims() != null && !authorizedToken.getClaims().isEmpty()) {
            tokenClaims = OAuth2TokenIntrospection.withClaims(
                    convertClaimsIfNecessary(authorizedToken.getClaims())).active(true);
        } else {
            tokenClaims = OAuth2TokenIntrospection.builder(true);
        }

        tokenClaims.clientId(authorizedClient.getClientId());
        // The default introspection response does not populate the username claim.
        OAuth2Token token = authorizedToken.getToken();
        if (token.getIssuedAt() != null) {
            tokenClaims.issuedAt(token.getIssuedAt());
        }
        if (token.getExpiresAt() != null) {
            tokenClaims.expiresAt(token.getExpiresAt());
        }
        if (token instanceof OAuth2AccessToken accessToken) {
            tokenClaims.tokenType(accessToken.getTokenType().getValue());
        }
        return tokenClaims.build();
    }

    private static Map<String, Object> convertClaimsIfNecessary(Map<String, Object> claims) {
        Map<String, Object> convertedClaims = new HashMap<>(claims);
        Object issuer = claims.get(OAuth2TokenIntrospectionClaimNames.ISS);
        if (issuer != null && !(issuer instanceof URL)) {
            try {
                convertedClaims.put(OAuth2TokenIntrospectionClaimNames.ISS,
                        new URI(issuer.toString()).toURL());
            } catch (Exception exception) {
                throw new IllegalArgumentException("iss must be a valid URL", exception);
            }
        }
        convertToStringList(convertedClaims, OAuth2TokenIntrospectionClaimNames.SCOPE, true);
        convertToStringList(convertedClaims, OAuth2TokenIntrospectionClaimNames.AUD, false);
        return convertedClaims;
    }

    private static void convertToStringList(Map<String, Object> claims, String name, boolean spaceDelimited) {
        Object value = claims.get(name);
        if (value == null || value instanceof List<?>) {
            return;
        }
        if (value instanceof Collection<?> collection) {
            claims.put(name, collection.stream().map(Object::toString).toList());
            return;
        }
        if (value instanceof Object[] values) {
            claims.put(name, Arrays.stream(values).map(Object::toString).toList());
            return;
        }
        claims.put(name, spaceDelimited
                ? Arrays.asList(value.toString().split(" "))
                : List.of(value.toString()));
    }
}
