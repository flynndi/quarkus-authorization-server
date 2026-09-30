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
package io.quarkiverse.authorization.server.runtime.grant.tokenexchange;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.jwt.Claims;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Validates a Token Exchange grant and issues a new access token. */
@Singleton
public final class TokenExchangeGrant {

    private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final String MAY_ACT = "may_act";

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final AuthorizationServerContext authorizationServerContext;
    private final DPoPTokenBinding dpop;

    @Inject
    public TokenExchangeGrant(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            AuthorizationServerContext authorizationServerContext,
            DPoPTokenBinding dpop) {
        this.dpop = Objects.requireNonNull(dpop);
        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.tokenGenerator = Objects.requireNonNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationServerContext = Objects.requireNonNull(
                authorizationServerContext, "authorizationServerContext cannot be null");
    }

    /**
     * Synchronous protocol work; the HTTP entry point supplies worker execution and a CDI request
     * context.
     */
    public TokenIssuanceResult exchange(TokenExchangeRequest request) {
        return exchange(request, null);
    }

    public TokenIssuanceResult exchange(
            TokenExchangeRequest request, DPoPProofRequest proofRequest) {
        Objects.requireNonNull(request, "request cannot be null");
        SecurityIdentity clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(
                request.getClientPrincipal());

        RegisteredClient registeredClient = clientPrincipal.getAttribute(
                OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
        if (!registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.TOKEN_EXCHANGE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        if (JWT_TOKEN_TYPE_VALUE.equals(request.getRequestedTokenType())
                && !OAuth2TokenFormat.SELF_CONTAINED.equals(
                        registeredClient.getTokenSettings().getAccessTokenFormat())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        OAuth2Authorization subjectAuthorization = this.authorizationService.findByToken(
                request.getSubjectToken(), OAuth2TokenType.ACCESS_TOKEN);
        if (subjectAuthorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        OAuth2Authorization.Token<OAuth2Token> subjectToken = subjectAuthorization.getToken(request.getSubjectToken());
        if (subjectToken == null || !subjectToken.isActive()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        validateDeclaredTokenType(request.getSubjectTokenType(), subjectToken);

        SecurityIdentity subjectPrincipal = subjectAuthorization.getAttribute(SecurityIdentity.class.getName());
        if (subjectPrincipal == null || subjectPrincipal.isAnonymous()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        Map<?, ?> authorizedActorClaims = null;
        if (subjectToken.getClaims() != null
                && subjectToken.getClaims().get(MAY_ACT) instanceof Map<?, ?> mayAct) {
            authorizedActorClaims = mayAct;
        }

        OAuth2Authorization actorAuthorization = null;
        if (Arguments.hasText(request.getActorToken())) {
            actorAuthorization = this.authorizationService.findByToken(
                    request.getActorToken(), OAuth2TokenType.ACCESS_TOKEN);
            if (actorAuthorization == null) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            OAuth2Authorization.Token<OAuth2Token> actorToken = actorAuthorization.getToken(request.getActorToken());
            if (actorToken == null || !actorToken.isActive()) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            validateDeclaredTokenType(request.getActorTokenType(), actorToken);
            if (authorizedActorClaims != null) {
                // may_act identifies the actor by token claims, not the application's login name.
                Map<String, Object> actorClaims = actorToken.getClaims();
                if (actorClaims == null
                        || !Objects.equals(authorizedActorClaims.get(Claims.iss.name()), actorClaims.get(Claims.iss.name()))
                        || !Objects.equals(authorizedActorClaims.get(Claims.sub.name()), actorClaims.get(Claims.sub.name()))) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
                }
            }
        } else if (authorizedActorClaims != null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        Set<String> authorizedScopes = Collections.emptySet();
        if (!request.getScopes().isEmpty()) {
            authorizedScopes = validateRequestedScopes(registeredClient, request.getScopes());
        } else if (!subjectAuthorization.getAuthorizedScopes().isEmpty()) {
            authorizedScopes = validateRequestedScopes(
                    registeredClient, subjectAuthorization.getAuthorizedScopes());
        }

        SecurityIdentity principal = getPrincipal(subjectPrincipal, actorAuthorization);
        // The optional DPoP proof binds only the issued token;
        // subject/actor cnf does not constrain the proof key or require a proof here.
        DPoPProof proof = this.dpop.verify(proofRequest, null);
        this.dpop.claim(proofRequest, proof);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(subjectAuthorization)
                .principal(principal)
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                this.authorizationServerContext))
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
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
                .principalName(subjectAuthorization.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(authorizedScopes)
                .attribute(SecurityIdentity.class.getName(), principal);
        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(
                authorizationBuilder, generatedAccessToken, tokenContext);

        this.authorizationService.save(authorizationBuilder.build());
        return new TokenIssuanceResult(
                registeredClient,
                clientPrincipal,
                accessToken,
                null,
                Map.of(OAuth2ParameterNames.ISSUED_TOKEN_TYPE, request.getRequestedTokenType()));
    }

    private static void validateDeclaredTokenType(
            String tokenType, OAuth2Authorization.Token<?> token) {
        Object format = token.getMetadata(OAuth2TokenFormat.class.getName());
        boolean jwt = OAuth2TokenFormat.SELF_CONTAINED.getValue().equals(format);
        boolean reference = OAuth2TokenFormat.REFERENCE.getValue().equals(format);
        // All locally issued access tokens must carry a supported issuance format.
        if ((!jwt && !reference) || (JWT_TOKEN_TYPE_VALUE.equals(tokenType) && !jwt)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private static Set<String> validateRequestedScopes(
            RegisteredClient registeredClient, Set<String> requestedScopes) {
        for (String requestedScope : requestedScopes) {
            if (!registeredClient.getScopes().contains(requestedScope)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        }
        return new LinkedHashSet<>(requestedScopes);
    }

    private static SecurityIdentity getPrincipal(
            SecurityIdentity subjectPrincipal, OAuth2Authorization actorAuthorization) {
        if (actorAuthorization == null) {
            return subjectPrincipal;
        }
        // Preserve token claims, including a customized sub, instead of substituting a login name.
        Map<String, Object> actorClaims = actorAuthorization.getAccessToken().getClaims();
        if (actorClaims == null
                || !(actorClaims.get(Claims.sub.name()) instanceof String subject)
                || subject.isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        List<Map<String, Object>> actors = new ArrayList<>();
        actors.add(Map.copyOf(actorClaims));
        actors.addAll(OAuth2TokenExchangeTokenCustomizers.getActors(subjectPrincipal));
        return QuarkusSecurityIdentity.builder(subjectPrincipal)
                .addAttribute(
                        OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE, List.copyOf(actors))
                .build();
    }
}
