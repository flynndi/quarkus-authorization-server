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
package io.quarkiverse.authorization.server.runtime.grant.clientcredentials;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequest;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.arc.All;
import io.quarkus.security.identity.SecurityIdentity;

/** Issues an access token for a validated Client Credentials grant. */
@Singleton
public final class ClientCredentialsGrant {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext authorizationServerContext;
    private final DPoPTokenBinding dpop;
    private final ClientCredentialsRequestValidator requestValidator;

    @Inject
    public ClientCredentialsGrant(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            AuthorizationServerContext authorizationServerContext,
            @All @Default List<ClientCredentialsRequestValidator> requestValidators,
            DPoPTokenBinding dpop) {
        this.dpop = Objects.requireNonNull(dpop);
        var requestValidatorsSnapshot = List.copyOf(requestValidators);

        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.tokenGenerator = Objects.requireNonNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationServerContext = Objects.requireNonNull(
                authorizationServerContext, "authorizationServerContext cannot be null");
        // @All supplies CDI-owned instances in descending priority order. @Default excludes
        // auxiliary qualified beans from this protocol chain.
        this.requestValidator = context -> requestValidatorsSnapshot.forEach(policy -> policy.validate(context));
    }

    /**
     * Runs validation, token generation and persistence synchronously. The grant handler supplies
     * the worker and CDI request context required by application SPIs.
     */
    public TokenIssuanceResult issueTokens(ClientCredentialsRequest request) {
        return issueTokens(request, null);
    }

    public TokenIssuanceResult issueTokens(
            ClientCredentialsRequest request, DPoPProofRequest proofRequest) {
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(
                request.getClientPrincipal());
        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);

        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        if (!registeredClient.getScopes().containsAll(request.getScopes())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
        this.requestValidator.validate(
                new ClientCredentialsRequestContext(request, registeredClient));

        // An omitted scope stays empty for this client-only grant; there is no resource-owner
        // authorization from which to inherit scopes.
        Set<String> authorizedScopes = new LinkedHashSet<>(request.getScopes());
        DPoPProof proof = this.dpop.verify(proofRequest, null);
        this.dpop.claim(proofRequest, proof);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(request);
        if (proof != null)
            tokenContextBuilder.put(DPoPProof.class, proof);
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate the access token.",
                            ERROR_URI));
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getPrincipal().getName())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(authorizedScopes);
        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(
                authorizationBuilder, generatedAccessToken, tokenContext);

        this.authorizationService.save(authorizationBuilder.build());

        return new TokenIssuanceResult(registeredClient, clientPrincipal, accessToken);
    }
}
