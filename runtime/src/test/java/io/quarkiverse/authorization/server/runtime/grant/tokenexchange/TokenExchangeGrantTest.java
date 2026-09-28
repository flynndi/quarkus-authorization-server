package io.quarkiverse.authorization.server.runtime.grant.tokenexchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class TokenExchangeGrantTest {

    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example.com").build();

    private final RegisteredClient exchangeClient = client(
            "exchange-registration",
            "exchange-client",
            OAuth2TokenFormat.SELF_CONTAINED,
            AuthorizationGrantType.TOKEN_EXCHANGE,
            Set.of("message.read", "message.write"));
    private final RegisteredClient subjectClient = client(
            "subject-registration",
            "subject-client",
            OAuth2TokenFormat.SELF_CONTAINED,
            AuthorizationGrantType.PASSWORD,
            Set.of("message.read"));
    private final RegisteredClient actorClient = client(
            "actor-registration",
            "actor-client",
            OAuth2TokenFormat.SELF_CONTAINED,
            AuthorizationGrantType.CLIENT_CREDENTIALS,
            Set.of());
    private final RecordingAuthorizationService authorizationService = new RecordingAuthorizationService();
    private final RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
    private final RegisteredClientRepository registeredClientRepository = new InMemoryRegisteredClientRepository(
            this.exchangeClient, this.subjectClient, this.actorClient);
    private final TokenExchangeGrant provider = new TokenExchangeGrant(
            this.authorizationService,
            this.tokenGenerator,
            new DefaultAuthorizationServerContext(SETTINGS),
            DPoPTestSupport.binding());

    @Test
    void exchangesLocalSubjectIntoIndependentAuthorization() {
        OAuth2Authorization subjectAuthorization = authorization(
                this.subjectClient,
                "subject-authorization",
                "alice",
                "subject-token",
                Set.of("message.read"),
                Map.of("sub", "alice"),
                user("alice"));
        this.authorizationService.add(subjectAuthorization);
        TokenExchangeRequest authentication = authentication(
                this.exchangeClient,
                "subject-token",
                ACCESS_TOKEN_TYPE,
                null,
                null,
                Set.of("message.write"),
                ACCESS_TOKEN_TYPE);

        TokenIssuanceResult result = this.provider.exchange(authentication);

        assertSame(this.exchangeClient, result.getRegisteredClient());
        assertEquals("exchanged-token", result.getAccessToken().getTokenValue());
        assertEquals(Set.of("message.write"), result.getAccessToken().getScopes());
        assertNull(result.getRefreshToken());
        assertEquals(
                Map.of(OAuth2ParameterNames.ISSUED_TOKEN_TYPE, ACCESS_TOKEN_TYPE),
                result.getAdditionalParameters());

        OAuth2TokenContext context = this.tokenGenerator.context;
        assertSame(subjectAuthorization, context.getAuthorization());
        assertSame(authentication, context.getAuthorizationGrant());
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE, context.getAuthorizationGrantType());
        assertEquals(OAuth2TokenType.ACCESS_TOKEN, context.getTokenType());
        assertEquals(Set.of("message.write"), context.getAuthorizedScopes());
        assertEquals("alice", context.getPrincipal().getPrincipal().getName());

        OAuth2Authorization saved = this.authorizationService.saved;
        assertNotNull(saved);
        assertNotSame(subjectAuthorization, saved);
        assertEquals(this.exchangeClient.getId(), saved.getRegisteredClientId());
        assertEquals("alice", saved.getPrincipalName());
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE, saved.getAuthorizationGrantType());
        assertEquals(Set.of("message.write"), saved.getAuthorizedScopes());
        assertEquals(this.tokenGenerator.token.getClaims(), saved.getAccessToken().getClaims());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                saved.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertNotNull(saved.getAttribute(SecurityIdentity.class.getName()));
        assertNull(saved.getRefreshToken());
        assertNull(saved.getToken(OidcIdToken.class));
        assertTrue(subjectAuthorization.getAccessToken().isActive());
        assertEquals(1, this.authorizationService.saveInvocations);
    }

    @Test
    void inheritsAllSubjectScopesWhenScopeIsOmitted() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));

        TokenIssuanceResult result = this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));

        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
        assertEquals(Set.of("message.read"), this.authorizationService.saved.getAuthorizedScopes());
    }

    @Test
    void doesNotIntersectRequestedOrInheritedScopesWithSubjectScopes() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));

        TokenIssuanceResult expanded = this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of("message.write"),
                        ACCESS_TOKEN_TYPE));
        assertEquals(Set.of("message.write"), expanded.getAccessToken().getScopes());

        RegisteredClient narrowExchangeClient = client(
                "narrow-exchange-registration",
                "narrow-exchange-client",
                OAuth2TokenFormat.SELF_CONTAINED,
                AuthorizationGrantType.TOKEN_EXCHANGE,
                Set.of("message.write"));
        assertError(
                this.provider,
                authentication(
                        narrowExchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_SCOPE);
    }

    @Test
    void createsDelegationChainFromActorTokenClaims() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        OAuth2Authorization actorAuthorization = authorization(
                this.actorClient,
                "actor-authorization",
                "actor-client",
                "actor-token",
                Set.of(),
                Map.of(),
                null);
        this.authorizationService.add(actorAuthorization);

        this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));

        SecurityIdentity principal = (SecurityIdentity) this.tokenGenerator.context.getPrincipal();
        assertEquals("alice", principal.getPrincipal().getName());
        assertEquals(Set.of("user"), principal.getRoles());
        assertEquals(
                List.of("actor-client"),
                OAuth2TokenExchangeTokenCustomizers.getActors(principal).stream()
                        .map(actor -> actor.get("sub"))
                        .toList());
        assertEquals(
                "actor-client",
                OAuth2TokenExchangeTokenCustomizers.getActors(principal).get(0).get("sub"));
        assertSame(
                principal,
                this.authorizationService.saved.getAttribute(SecurityIdentity.class.getName()));
        assertTrue(actorAuthorization.getAccessToken().isActive());
    }

    @ParameterizedTest
    @ValueSource(strings = { "missing", "blank", "non-string" })
    void rejectsActorWithoutUsableSubjectClaimBeforeIssuance(String kind) {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        OAuth2Authorization actor = authorization(
                this.actorClient,
                "actor",
                "actor-login",
                "actor-token",
                Set.of(),
                Map.of(),
                null);
        actor = OAuth2Authorization.from(actor)
                .token(
                        actor.getAccessToken().getToken(),
                        metadata -> {
                            if ("missing".equals(kind))
                                metadata.remove(
                                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
                            else
                                metadata.put(
                                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                        Map.of("sub", "blank".equals(kind) ? " " : 5));
                        })
                .build();
        this.authorizationService.add(actor);

        OAuth2AuthenticationException failure = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.provider.exchange(
                        authentication(
                                this.exchangeClient,
                                "subject-token",
                                ACCESS_TOKEN_TYPE,
                                "actor-token",
                                ACCESS_TOKEN_TYPE,
                                Set.of(),
                                ACCESS_TOKEN_TYPE)));

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, failure.getError().getErrorCode());
        assertEquals(0, this.tokenGenerator.invocations);
        assertEquals(0, this.authorizationService.saveInvocations);
    }

    @Test
    void capturesActorTokenClaimsWithoutReplacingCustomizedSubjectWithLoginName() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        Map<String, Object> actorClaims = Map.of(
                "sub",
                "public-actor-subject",
                "iss",
                "https://actor.example",
                "aud",
                List.of("api"));
        this.authorizationService.add(
                authorization(
                        this.actorClient,
                        "actor",
                        "actor-login",
                        "actor-token",
                        Set.of(),
                        actorClaims,
                        null));

        this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));

        SecurityIdentity principal = this.tokenGenerator.context.getPrincipal();
        assertEquals("alice", principal.getPrincipal().getName());
        assertEquals(
                List.of(actorClaims), OAuth2TokenExchangeTokenCustomizers.getActors(principal));
    }

    @Test
    void prependsCurrentActorAndPreservesExistingDelegationChain() {
        SecurityIdentity subject = user("alice");
        SecurityIdentity previous = QuarkusSecurityIdentity.builder(subject)
                .addAttribute(
                        OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE,
                        List.of(Map.of("sub", "previous-actor")))
                .build();
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        previous));
        this.authorizationService.add(
                authorization(
                        this.actorClient,
                        "actor-authorization",
                        "actor-client",
                        "actor-token",
                        Set.of(),
                        Map.of(),
                        null));

        this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));

        SecurityIdentity result = (SecurityIdentity) this.tokenGenerator.context.getPrincipal();
        assertEquals(subject.getPrincipal().getName(), result.getPrincipal().getName());
        assertEquals(subject.getRoles(), result.getRoles());
        assertEquals(
                List.of("actor-client", "previous-actor"),
                OAuth2TokenExchangeTokenCustomizers.getActors(result).stream()
                        .map(actor -> actor.get("sub"))
                        .toList());
    }

    @Test
    void preservesPreviousActorsWhenCurrentExchangeOmitsActor() {
        SecurityIdentity previous = QuarkusSecurityIdentity.builder(user("alice"))
                .addAttribute(
                        OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE,
                        List.of(Map.of("sub", "previous-actor")))
                .build();
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        previous));

        this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));

        SecurityIdentity result = (SecurityIdentity) this.tokenGenerator.context.getPrincipal();
        assertEquals(
                List.of("previous-actor"),
                OAuth2TokenExchangeTokenCustomizers.getActors(result).stream()
                        .map(actor -> actor.get("sub"))
                        .toList());
    }

    @Test
    void enforcesMayActAgainstActorOrAuthenticatedClient() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of("may_act", Map.of("sub", "actor-client")),
                        user("alice")));
        this.authorizationService.add(
                authorization(
                        this.actorClient,
                        "actor-authorization",
                        "actor-client",
                        "actor-token",
                        Set.of(),
                        Map.of(),
                        null));
        this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));

        RegisteredClient wrongActor = client(
                "wrong-actor-registration",
                "wrong-actor",
                OAuth2TokenFormat.SELF_CONTAINED,
                AuthorizationGrantType.CLIENT_CREDENTIALS,
                Set.of());
        this.authorizationService.add(
                authorization(
                        wrongActor,
                        "wrong-actor-authorization",
                        "wrong-actor",
                        "wrong-actor-token",
                        Set.of(),
                        Map.of(),
                        null));
        assertError(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "wrong-actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);
        assertError(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);

        RecordingAuthorizationService directService = new RecordingAuthorizationService();
        directService.add(
                authorization(
                        this.subjectClient,
                        "direct-subject-authorization",
                        "alice",
                        "direct-subject-token",
                        Set.of("message.read"),
                        Map.of("may_act", Map.of("sub", "exchange-client")),
                        user("alice")));
        TokenExchangeGrant directProvider = new TokenExchangeGrant(
                directService,
                new RecordingTokenGenerator(),
                new DefaultAuthorizationServerContext(SETTINGS),
                DPoPTestSupport.binding());
        directProvider.exchange(
                authentication(
                        this.exchangeClient,
                        "direct-subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));
        assertNotNull(directService.saved);
    }

    @Test
    void rejectsInvalidClientOrUnauthorizedGrant() {
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder()
                .setAnonymous(true)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        this.exchangeClient)
                .build();
        assertError(
                new TokenExchangeRequest(
                        List.of(),
                        List.of(),
                        Set.of(),
                        ACCESS_TOKEN_TYPE,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        anonymous,
                        Map.of()),
                OAuth2ErrorCodes.INVALID_CLIENT);

        RegisteredClient unauthorized = client(
                "unauthorized-registration",
                "unauthorized-client",
                OAuth2TokenFormat.SELF_CONTAINED,
                AuthorizationGrantType.CLIENT_CREDENTIALS,
                Set.of());
        assertError(
                authentication(
                        unauthorized,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    @Test
    void rejectsUnknownInactiveOrPrincipalLessSubject() {
        assertError(
                authentication(
                        this.exchangeClient,
                        "unknown-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);

        OAuth2Authorization inactive = authorization(
                this.subjectClient,
                "inactive-authorization",
                "alice",
                "inactive-token",
                Set.of("message.read"),
                Map.of(),
                user("alice"));
        inactive = OAuth2Authorization.from(inactive)
                .token(
                        inactive.getAccessToken().getToken(),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                true))
                .build();
        this.authorizationService.add(inactive);
        assertError(
                authentication(
                        this.exchangeClient,
                        "inactive-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);

        OAuth2Authorization expired = expire(
                authorization(
                        this.subjectClient,
                        "expired-authorization",
                        "alice",
                        "expired-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        this.authorizationService.add(expired);
        assertError(
                authentication(
                        this.exchangeClient,
                        "expired-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);

        this.authorizationService.add(
                authorization(
                        this.actorClient,
                        "client-credentials-authorization",
                        "actor-client",
                        "client-subject-token",
                        Set.of(),
                        Map.of(),
                        null));
        assertError(
                authentication(
                        this.exchangeClient,
                        "client-subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    void rejectsUnknownOrInactiveActor() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        assertError(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "unknown-actor",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);

        OAuth2Authorization inactive = authorization(
                this.actorClient,
                "inactive-actor-authorization",
                "actor-client",
                "inactive-actor-token",
                Set.of(),
                Map.of(),
                null);
        inactive = OAuth2Authorization.from(inactive)
                .token(
                        inactive.getAccessToken().getToken(),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                true))
                .build();
        this.authorizationService.add(inactive);
        assertError(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "inactive-actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);

        OAuth2Authorization expired = expire(
                authorization(
                        this.actorClient,
                        "expired-actor-authorization",
                        "actor-client",
                        "expired-actor-token",
                        Set.of(),
                        Map.of(),
                        null));
        this.authorizationService.add(expired);
        assertError(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "expired-actor-token",
                        ACCESS_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    void validatesDeclaredJwtAgainstIssuedTokenFormat() {
        RegisteredClient referenceSubject = client(
                "reference-subject-registration",
                "reference-subject",
                OAuth2TokenFormat.REFERENCE,
                AuthorizationGrantType.PASSWORD,
                Set.of("message.read"));
        this.authorizationService.add(
                authorization(
                        referenceSubject,
                        "reference-subject-authorization",
                        "alice",
                        "reference-subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        assertError(
                authentication(
                        this.exchangeClient,
                        "reference-subject-token",
                        JWT_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_REQUEST);
        this.provider.exchange(
                authentication(
                        this.exchangeClient,
                        "reference-subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE));
        assertEquals(1, this.tokenGenerator.invocations);
    }

    @Test
    void validatesActorJwtAgainstIssuedTokenFormat() {
        RegisteredClient referenceActor = client(
                "reference-actor-registration",
                "reference-actor",
                OAuth2TokenFormat.REFERENCE,
                AuthorizationGrantType.CLIENT_CREDENTIALS,
                Set.of());
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        this.authorizationService.add(
                authorization(
                        referenceActor,
                        "reference-actor-authorization",
                        "reference-actor",
                        "reference-actor-token",
                        Set.of(),
                        Map.of(),
                        null));
        assertError(
                authentication(
                        this.exchangeClient,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        "reference-actor-token",
                        JWT_TOKEN_TYPE,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_REQUEST);
    }

    @ParameterizedTest
    @CsvSource({ "false, true", "false, false", "true, true", "true, false" })
    void usesIssuedFormatAfterSourceClientConfigurationChanges(boolean actor, boolean issuedJwt) {
        RegisteredClient sourceClient = actor ? this.actorClient : this.subjectClient;
        OAuth2TokenFormat issuedFormat = issuedJwt ? OAuth2TokenFormat.SELF_CONTAINED : OAuth2TokenFormat.REFERENCE;
        RegisteredClient issuedClient = RegisteredClient.from(sourceClient)
                .tokenSettings(
                        TokenSettings.builder().accessTokenFormat(issuedFormat).build())
                .build();
        this.authorizationService.add(
                authorization(
                        actor ? this.subjectClient : issuedClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        if (actor) {
            this.authorizationService.add(
                    authorization(
                            issuedClient,
                            "actor-authorization",
                            "actor-client",
                            "actor-token",
                            Set.of(),
                            Map.of(),
                            null));
        }
        this.registeredClientRepository.save(
                RegisteredClient.from(issuedClient)
                        .tokenSettings(
                                TokenSettings.builder()
                                        .accessTokenFormat(
                                                issuedJwt
                                                        ? OAuth2TokenFormat.REFERENCE
                                                        : OAuth2TokenFormat.SELF_CONTAINED)
                                        .build())
                        .build());

        TokenExchangeRequest jwtDeclaration = authentication(
                this.exchangeClient,
                "subject-token",
                actor ? ACCESS_TOKEN_TYPE : JWT_TOKEN_TYPE,
                actor ? "actor-token" : null,
                actor ? JWT_TOKEN_TYPE : null,
                Set.of(),
                ACCESS_TOKEN_TYPE);
        if (issuedJwt) {
            assertNotNull(this.provider.exchange(jwtDeclaration));
        } else {
            assertError(jwtDeclaration, OAuth2ErrorCodes.INVALID_REQUEST);
            assertEquals(0, this.tokenGenerator.invocations);
        }
        assertNotNull(
                this.provider.exchange(
                        authentication(
                                this.exchangeClient,
                                "subject-token",
                                ACCESS_TOKEN_TYPE,
                                actor ? "actor-token" : null,
                                actor ? ACCESS_TOKEN_TYPE : null,
                                Set.of(),
                                ACCESS_TOKEN_TYPE)));
    }

    @ParameterizedTest
    @CsvSource({
            "false, missing",
            "false, unknown",
            "false, nonstring",
            "true, missing",
            "true, unknown",
            "true, nonstring"
    })
    void rejectsMissingOrMalformedFormatForBothInputTypes(boolean actor, String metadataKind) {
        OAuth2Authorization subject = authorization(
                this.subjectClient,
                "subject-authorization",
                "alice",
                actor ? "subject-token" : "looks.like.jwt",
                Set.of("message.read"),
                Map.of(),
                user("alice"));
        OAuth2Authorization source = actor
                ? authorization(
                        this.actorClient,
                        "actor-authorization",
                        "actor-client",
                        "looks.like.jwt",
                        Set.of(),
                        Map.of(),
                        null)
                : subject;
        source = OAuth2Authorization.from(source)
                .token(
                        source.getAccessToken().getToken(),
                        metadata -> {
                            metadata.remove(OAuth2TokenFormat.class.getName());
                            if (!"missing".equals(metadataKind)) {
                                metadata.put(
                                        OAuth2TokenFormat.class.getName(),
                                        "unknown".equals(metadataKind) ? "unknown" : 42);
                            }
                        })
                .build();
        this.authorizationService.add(subject);
        this.authorizationService.add(source);

        assertError(
                authentication(
                        this.exchangeClient,
                        actor ? "subject-token" : "looks.like.jwt",
                        actor ? ACCESS_TOKEN_TYPE : JWT_TOKEN_TYPE,
                        actor ? "looks.like.jwt" : null,
                        actor ? JWT_TOKEN_TYPE : null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertError(
                authentication(
                        this.exchangeClient,
                        actor ? "subject-token" : "looks.like.jwt",
                        ACCESS_TOKEN_TYPE,
                        actor ? "looks.like.jwt" : null,
                        actor ? ACCESS_TOKEN_TYPE : null,
                        Set.of(),
                        ACCESS_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertEquals(0, this.tokenGenerator.invocations);
        assertEquals(0, this.authorizationService.saveInvocations);
    }

    @Test
    void rejectsJwtOutputForReferenceExchangeClient() {
        RegisteredClient referenceExchange = client(
                "reference-exchange-registration",
                "reference-exchange",
                OAuth2TokenFormat.REFERENCE,
                AuthorizationGrantType.TOKEN_EXCHANGE,
                Set.of("message.read"));
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));

        assertError(
                authentication(
                        referenceExchange,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        Set.of(),
                        JWT_TOKEN_TYPE),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertEquals(0, this.authorizationService.findInvocations);
    }

    @Test
    void generationAndSaveFailuresDoNotReturnSuccess() {
        this.authorizationService.add(
                authorization(
                        this.subjectClient,
                        "subject-authorization",
                        "alice",
                        "subject-token",
                        Set.of("message.read"),
                        Map.of(),
                        user("alice")));
        TokenExchangeRequest authentication = authentication(
                this.exchangeClient,
                "subject-token",
                ACCESS_TOKEN_TYPE,
                null,
                null,
                Set.of(),
                ACCESS_TOKEN_TYPE);

        RecordingTokenGenerator nullGenerator = new RecordingTokenGenerator();
        nullGenerator.returnNull = true;
        OAuth2AuthenticationException generationFailure = assertThrows(
                OAuth2AuthenticationException.class,
                () -> new TokenExchangeGrant(
                        this.authorizationService,
                        nullGenerator,
                        new DefaultAuthorizationServerContext(SETTINGS),
                        DPoPTestSupport.binding())
                        .exchange(authentication));
        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, generationFailure.getError().getErrorCode());
        assertEquals(0, this.authorizationService.saveInvocations);

        this.authorizationService.failure = new IllegalStateException("save failed");
        assertSame(
                this.authorizationService.failure,
                assertThrows(
                        IllegalStateException.class, () -> this.provider.exchange(authentication)));
        assertEquals(1, this.authorizationService.saveInvocations);
        assertNull(
                this.authorizationService.delegate.findByToken(
                        "exchanged-token", OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void requiresAuthenticationAndDependencies() {
        assertThrows(NullPointerException.class, () -> this.provider.exchange(null));
        assertThrows(
                NullPointerException.class,
                () -> new TokenExchangeGrant(
                        null, this.tokenGenerator, new DefaultAuthorizationServerContext(SETTINGS), DPoPTestSupport.binding()));
        assertThrows(
                NullPointerException.class,
                () -> new TokenExchangeGrant(
                        this.authorizationService,
                        null,
                        new DefaultAuthorizationServerContext(SETTINGS),
                        DPoPTestSupport.binding()));
        assertThrows(
                NullPointerException.class,
                () -> new TokenExchangeGrant(
                        this.authorizationService,
                        this.tokenGenerator,
                        null,
                        DPoPTestSupport.binding()));
    }

    private void assertError(TokenExchangeRequest authentication, String errorCode) {
        assertError(this.provider, authentication, errorCode);
    }

    private static void assertError(
            TokenExchangeGrant provider, TokenExchangeRequest authentication, String errorCode) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(authentication));
        assertEquals(errorCode, exception.getError().getErrorCode());
    }

    private static TokenExchangeRequest authentication(
            RegisteredClient client,
            String subjectToken,
            String subjectTokenType,
            String actorToken,
            String actorTokenType,
            Set<String> scopes,
            String requestedTokenType) {
        return new TokenExchangeRequest(
                List.of(),
                List.of("messages-api"),
                scopes,
                requestedTokenType,
                subjectToken,
                subjectTokenType,
                actorToken,
                actorTokenType,
                clientIdentity(client),
                Map.of("custom", "value"));
    }

    private static OAuth2Authorization authorization(
            RegisteredClient client,
            String id,
            String principalName,
            String tokenValue,
            Set<String> scopes,
            Map<String, Object> claims,
            SecurityIdentity principal) {
        Instant issuedAt = Instant.now().minusSeconds(30);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenValue,
                issuedAt,
                issuedAt.plusSeconds(300),
                scopes);
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName(principalName)
                .authorizationGrantType(
                        client.getAuthorizationGrantTypes().iterator().next())
                .authorizedScopes(scopes)
                .token(
                        accessToken,
                        metadata -> {
                            metadata.put(
                                    OAuth2TokenFormat.class.getName(),
                                    client.getTokenSettings()
                                            .getAccessTokenFormat()
                                            .getValue());
                            Map<String, Object> tokenClaims = new LinkedHashMap<>(claims);
                            tokenClaims.putIfAbsent("sub", principalName);
                            metadata.put(
                                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                    tokenClaims);
                        });
        if (principal != null) {
            builder.attribute(SecurityIdentity.class.getName(), principal);
        }
        return builder.build();
    }

    private static SecurityIdentity user(String name) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(name))
                .addRoles(Set.of("user"))
                .build();
    }

    private static OAuth2Authorization expire(OAuth2Authorization authorization) {
        OAuth2AccessToken token = authorization.getAccessToken().getToken();
        OAuth2AccessToken expired = new OAuth2AccessToken(
                token.getTokenType(),
                token.getTokenValue(),
                token.getIssuedAt(),
                Instant.now().minusSeconds(1),
                token.getScopes());
        return OAuth2Authorization.from(authorization).accessToken(expired).build();
    }

    private static SecurityIdentity clientIdentity(RegisteredClient client) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(client.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .build();
    }

    private static RegisteredClient client(
            String id,
            String clientId,
            OAuth2TokenFormat format,
            AuthorizationGrantType grantType,
            Set<String> scopes) {
        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(clientId)
                .authorizationGrantType(grantType)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(format).build());
        scopes.forEach(builder::scope);
        return builder.build();
    }

    private static final class RecordingTokenGenerator
            implements OAuth2TokenGenerator<OAuth2Token> {

        private OAuth2TokenContext context;
        private Jwt token;
        private int invocations;
        private boolean returnNull;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            this.context = context;
            this.invocations++;
            if (this.returnNull) {
                return null;
            }
            Instant issuedAt = Instant.now();
            this.token = new Jwt(
                    "exchanged-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    Map.of("alg", "RS256"),
                    Map.of(
                            "sub",
                            context.getPrincipal().getPrincipal().getName(),
                            "aud",
                            List.of(context.getRegisteredClient().getClientId()),
                            OAuth2ParameterNames.SCOPE,
                            context.getAuthorizedScopes()));
            return this.token;
        }
    }

    private static final class RecordingAuthorizationService implements OAuth2AuthorizationService {

        private final InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
        private OAuth2Authorization saved;
        private int saveInvocations;
        private int findInvocations;
        private RuntimeException failure;

        private void add(OAuth2Authorization authorization) {
            this.delegate.save(authorization);
        }

        @Override
        public void save(OAuth2Authorization authorization) {
            this.saveInvocations++;
            if (this.failure != null) {
                throw this.failure;
            }
            this.saved = authorization;
            this.delegate.save(authorization);
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
            this.delegate.remove(authorization);
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return this.delegate.findById(id);
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            this.findInvocations++;
            return this.delegate.findByToken(token, tokenType);
        }
    }
}
