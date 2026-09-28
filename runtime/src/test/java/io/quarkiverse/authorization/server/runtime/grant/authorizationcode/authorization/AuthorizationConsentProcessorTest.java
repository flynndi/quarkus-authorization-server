package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentCustomizer;
import io.quarkiverse.authorization.server.grant.authorizationcode.ConsentSubmission;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationConsentProcessorTest {

    private static final String INTERNAL_STATE = "internal-consent-state";
    private static final SecurityIdentity PRINCIPAL = identity("resource-owner");
    private static final AuthorizationServerSettings AUTHORIZATION_SERVER_SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example.com").build();

    @Test
    void explicitDenialRunsCustomizerBeforeCancellingAndPreservesPreviousConsentByDefault() {
        RegisteredClient client = AuthorizationConsentProcessorTest.registeredClient(Set.of("message.read", "message.write"));
        OAuth2Authorization pending = AuthorizationConsentProcessorTest.authorization(client,
                Set.of("message.read", "message.write"));
        OAuth2AuthorizationConsent previous = OAuth2AuthorizationConsent.withId(client.getId(), "resource-owner")
                .scope("message.read").build();
        var authorizations = new InMemoryOAuth2AuthorizationService(pending);
        var consents = new InMemoryOAuth2AuthorizationConsentService(previous);
        AtomicBoolean customized = new AtomicBoolean();
        var processor = AuthorizationConsentProcessorTest.provider(client, authorizations, consents,
                new DefaultAuthorizationCodeGenerator(), context -> {
                    customized.set(true);
                    assertTrue(context.getSubmission().isDenied());
                    assertEquals(AuthorizationConsentContext.Decision.DENY, context.getDecision());
                    assertSame(pending, authorizations.findById(pending.getId()));
                    assertSame(previous, consents.findById(client.getId(), "resource-owner"));
                    context.getAuthorizationConsent().authority("permission:customized");
                });
        var denial = new ConsentSubmission("https://issuer.example.com/oauth2/authorize", client.getClientId(),
                PRINCIPAL, INTERNAL_STATE, Set.of("message.write"),
                Map.of(ConsentSubmission.ACTION_PARAMETER, ConsentSubmission.DENY_ACTION));

        AuthorizationRequestException error = assertThrows(AuthorizationRequestException.class,
                () -> processor.consent(denial));

        assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, error.getError().getErrorCode());
        assertEquals("client-state", error.getRedirect().state());
        assertNull(authorizations.findById(pending.getId()));
        assertSame(previous, consents.findById(client.getId(), "resource-owner"));
        assertTrue(customized.get());
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST,
                assertThrows(AuthorizationRequestException.class, () -> processor.consent(denial)).getError().getErrorCode());
    }

    @Test
    void invalidDenialDoesNotCancelAnotherUsersOrClientsPendingRequest() {
        RegisteredClient client = AuthorizationConsentProcessorTest.registeredClient(Set.of("message.read"));
        OAuth2Authorization pending = AuthorizationConsentProcessorTest.authorization(client, Set.of("message.read"));
        var authorizations = new InMemoryOAuth2AuthorizationService(pending);
        AtomicBoolean customized = new AtomicBoolean();
        var processor = AuthorizationConsentProcessorTest.provider(client, authorizations,
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationCodeGenerator(), context -> customized.set(true));
        for (ConsentSubmission denial : java.util.List.of(
                new ConsentSubmission("https://issuer.example.com/oauth2/authorize", client.getClientId(),
                        AuthorizationConsentProcessorTest.identity("other-user"), INTERNAL_STATE, Set.of(),
                        Map.of(ConsentSubmission.ACTION_PARAMETER, ConsentSubmission.DENY_ACTION)),
                new ConsentSubmission("https://issuer.example.com/oauth2/authorize", "other-client", PRINCIPAL,
                        INTERNAL_STATE, Set.of(), Map.of(ConsentSubmission.ACTION_PARAMETER, ConsentSubmission.DENY_ACTION)))) {
            AuthorizationRequestException error = assertThrows(AuthorizationRequestException.class,
                    () -> processor.consent(denial));
            assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getError().getErrorCode());
            assertNull(error.getRedirect());
            assertSame(pending, authorizations.findById(pending.getId()));
        }
        assertFalse(customized.get());
    }

    @Test
    void customizerCanChangeDenialToApprovalAndItsScopesReachTheCode() {
        RegisteredClient client = AuthorizationConsentProcessorTest
                .registeredClient(Set.of("message.read", "message.write", "other.scope"));
        OAuth2Authorization pending = AuthorizationConsentProcessorTest.authorization(client,
                Set.of("message.read", "message.write"));
        var authorizations = new InMemoryOAuth2AuthorizationService(pending);
        var consents = new InMemoryOAuth2AuthorizationConsentService();
        AtomicReference<OAuth2TokenContext> generatedContext = new AtomicReference<>();
        var processor = AuthorizationConsentProcessorTest.provider(client, authorizations, consents, context -> {
            generatedContext.set(context);
            return new DefaultAuthorizationCodeGenerator().generate(context);
        }, context -> {
            context.setDecision(AuthorizationConsentContext.Decision.APPROVE);
            // Keep the original browser input available after customizing the final decision.
            assertTrue(context.getSubmission().isDenied());
            context.getAuthorizationConsent().authorities(Set::clear);
            context.getAuthorizationConsent().scope("message.read").scope("other.scope");
        });
        var denial = new ConsentSubmission("https://issuer.example.com/oauth2/authorize", client.getClientId(),
                PRINCIPAL, INTERNAL_STATE, Set.of("message.write"),
                Map.of(ConsentSubmission.ACTION_PARAMETER, ConsentSubmission.DENY_ACTION));

        AuthorizationOutcome.CodeIssued result = processor.consent(denial);

        assertEquals(Set.of("message.read"), result.scopes());
        assertEquals(Set.of("message.read"), generatedContext.get().getAuthorizedScopes());
        assertEquals(Set.of("message.read"), authorizations.findById(pending.getId()).getAuthorizedScopes());
        assertEquals(Set.of("message.read", "other.scope"), consents.findById(client.getId(), "resource-owner").getScopes());
    }

    @Test
    void customizerCanDenyAnApprovalWithoutRevokingHistoricalConsent() {
        RegisteredClient client = AuthorizationConsentProcessorTest.registeredClient(Set.of("message.read", "message.write"));
        OAuth2Authorization pending = AuthorizationConsentProcessorTest.authorization(client,
                Set.of("message.read", "message.write"));
        OAuth2AuthorizationConsent previous = OAuth2AuthorizationConsent.withId(client.getId(), "resource-owner")
                .scope("message.read").build();
        var authorizations = new InMemoryOAuth2AuthorizationService(pending);
        var consents = new InMemoryOAuth2AuthorizationConsentService(previous);
        var processor = AuthorizationConsentProcessorTest.provider(client, authorizations, consents,
                new DefaultAuthorizationCodeGenerator(), context -> {
                    assertEquals(AuthorizationConsentContext.Decision.APPROVE, context.getDecision());
                    context.setDecision(AuthorizationConsentContext.Decision.DENY);
                });

        AuthorizationRequestException error = assertThrows(AuthorizationRequestException.class,
                () -> processor.consent(AuthorizationConsentProcessorTest.consent(PRINCIPAL, Set.of("message.write"))));

        assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, error.getError().getErrorCode());
        assertSame(previous, consents.findById(client.getId(), "resource-owner"));
        assertNull(authorizations.findById(pending.getId()));
    }

    @ParameterizedTest
    @ValueSource(strings = { ConsentSubmission.APPROVE_ACTION, ConsentSubmission.DENY_ACTION })
    void clearingAuthoritiesRevokesHistoricalConsentAfterEitherFormAction(String action) {
        RegisteredClient client = AuthorizationConsentProcessorTest.registeredClient(Set.of("message.read", "message.write"));
        OAuth2Authorization pending = AuthorizationConsentProcessorTest.authorization(client,
                Set.of("message.read", "message.write"));
        OAuth2AuthorizationConsent previous = OAuth2AuthorizationConsent.withId(client.getId(), "resource-owner")
                .scope("message.read").build();
        var authorizations = new InMemoryOAuth2AuthorizationService(pending);
        var consents = new InMemoryOAuth2AuthorizationConsentService(previous);
        var processor = AuthorizationConsentProcessorTest.provider(client, authorizations, consents,
                new DefaultAuthorizationCodeGenerator(), context -> context.getAuthorizationConsent().authorities(Set::clear));
        var submission = new ConsentSubmission("https://issuer.example.com/oauth2/authorize", client.getClientId(),
                PRINCIPAL, INTERNAL_STATE, Set.of("message.write"), Map.of(ConsentSubmission.ACTION_PARAMETER, action));

        AuthorizationRequestException error = assertThrows(AuthorizationRequestException.class,
                () -> processor.consent(submission));

        assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, error.getError().getErrorCode());
        assertNull(authorizations.findById(pending.getId()));
        assertNull(consents.findById(client.getId(), "resource-owner"));
    }

    @Test
    void invalidScopesOnADenialAreRejectedBeforeCustomizationOrMutation() {
        RegisteredClient client = AuthorizationConsentProcessorTest.registeredClient(Set.of("message.read", "message.write"));
        OAuth2Authorization pending = AuthorizationConsentProcessorTest.authorization(client, Set.of("message.read"));
        var authorizations = new InMemoryOAuth2AuthorizationService(pending);
        AtomicBoolean customized = new AtomicBoolean();
        var processor = AuthorizationConsentProcessorTest.provider(client, authorizations,
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationCodeGenerator(), context -> customized.set(true));
        var denial = new ConsentSubmission("https://issuer.example.com/oauth2/authorize", client.getClientId(),
                PRINCIPAL, INTERNAL_STATE, Set.of("message.write"),
                Map.of(ConsentSubmission.ACTION_PARAMETER, ConsentSubmission.DENY_ACTION));

        AuthorizationRequestException error = assertThrows(AuthorizationRequestException.class,
                () -> processor.consent(denial));

        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getError().getErrorCode());
        assertFalse(customized.get());
        assertSame(pending, authorizations.findById(pending.getId()));
    }

    @Test
    void rejectsUnknownConsentStateWithoutRedirecting() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read"));
        AuthorizationConsentProcessor provider = provider(
                registeredClient,
                new InMemoryOAuth2AuthorizationService(),
                new InMemoryOAuth2AuthorizationConsentService());

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.consent(consent(PRINCIPAL, Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertNull(exception.getRedirect());
    }

    @Test
    void rejectsConsentSubmittedByAnotherPrincipal() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read"));
        OAuth2Authorization authorization = authorization(registeredClient, Set.of("message.read"));
        AuthorizationConsentProcessor provider = provider(
                registeredClient,
                new InMemoryOAuth2AuthorizationService(authorization),
                new InMemoryOAuth2AuthorizationConsentService());

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.consent(
                        consent(identity("other-user"), Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertNull(exception.getRedirect());
    }

    @Test
    void rejectsScopeThatWasNotRequested() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read", "message.write"));
        OAuth2Authorization authorization = authorization(registeredClient, Set.of("message.read"));
        AuthorizationConsentProcessor provider = provider(
                registeredClient,
                new InMemoryOAuth2AuthorizationService(authorization),
                new InMemoryOAuth2AuthorizationConsentService());

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.consent(consent(PRINCIPAL, Set.of("message.write"))));

        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, exception.getError().getErrorCode());
        assertEquals("https://client.example.com/callback", exception.getRedirect().uri());
        assertEquals("client-state", exception.getRedirect().state());
    }

    @Test
    void deniesConsentAndRemovesInFlightAuthorizationWhenNoScopeIsApproved() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read"));
        OAuth2Authorization authorization = authorization(registeredClient, Set.of("message.read"));
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(authorization);
        AuthorizationConsentProcessor provider = provider(
                registeredClient,
                authorizationService,
                new InMemoryOAuth2AuthorizationConsentService());

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.consent(consent(PRINCIPAL, Set.of())));

        assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, exception.getError().getErrorCode());
        assertEquals("https://client.example.com/callback", exception.getRedirect().uri());
        assertNull(authorizationService.findById(authorization.getId()));
    }

    @Test
    void mergesPreviouslyAuthorizedScopesAndPersistsConsent() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read", "message.write"));
        OAuth2Authorization authorization = authorization(registeredClient, Set.of("message.read", "message.write"));
        OAuth2AuthorizationConsent previousConsent = OAuth2AuthorizationConsent
                .withId(registeredClient.getId(), "resource-owner")
                .scope("message.read")
                .build();
        InMemoryOAuth2AuthorizationConsentService consentService = new InMemoryOAuth2AuthorizationConsentService(
                previousConsent);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(authorization);
        AuthorizationConsentProcessor provider = provider(registeredClient, authorizationService, consentService);

        AuthorizationOutcome.CodeIssued result = provider.consent(consent(PRINCIPAL, Set.of("message.write")));

        assertTrue(result.code().getExpiresAt().isAfter(result.code().getIssuedAt()));
        assertEquals(Set.of("message.read", "message.write"), result.scopes());
        assertEquals("client-state", result.state());
        OAuth2AuthorizationConsent savedConsent = consentService.findById(registeredClient.getId(), "resource-owner");
        assertEquals(Set.of("message.read", "message.write"), savedConsent.getScopes());
        OAuth2Authorization savedAuthorization = authorizationService.findById(authorization.getId());
        assertEquals(
                Set.of("message.read", "message.write"), savedAuthorization.getAuthorizedScopes());
        assertEquals(result.code(), savedAuthorization.getAuthorizationCode().getToken());
        assertNull(savedAuthorization.getAttribute(OAuth2ParameterNames.STATE));
    }

    @Test
    void supportsAuthorizationConsentCustomization() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read"));
        OAuth2Authorization authorization = authorization(registeredClient, Set.of("message.read"));
        AtomicBoolean customized = new AtomicBoolean();
        AuthorizationConsentProcessor provider = provider(
                registeredClient,
                new InMemoryOAuth2AuthorizationService(authorization),
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationCodeGenerator(),
                context -> {
                    customized.set(true);
                    assertSame(authorization, context.getAuthorization());
                    assertEquals(registeredClient, context.getRegisteredClient());
                    context.getAuthorizationConsent().authority("permission:messages");
                });

        provider.consent(consent(PRINCIPAL, Set.of("message.read")));

        assertTrue(customized.get());
    }

    @Test
    void consentUsesTheApprovingSessionRatherThanAnEarlierLogin() {
        RegisteredClient client = registeredClient(Set.of("openid", "message.read"));
        var previous = new SessionInformation(
                "resource-owner", "previous", Instant.now().minusSeconds(100));
        var current = new SessionInformation("resource-owner", "current", Instant.now());
        String attribute = SessionInformation.class.getName();
        OAuth2Authorization pending = OAuth2Authorization.from(authorization(client, Set.of("openid", "message.read")))
                .attribute(attribute, previous)
                .build();
        var service = new InMemoryOAuth2AuthorizationService(pending);
        var provider = provider(client, service, new InMemoryOAuth2AuthorizationConsentService());
        provider.consent(
                consent(
                        QuarkusSecurityIdentity.builder(PRINCIPAL)
                                .addAttribute(attribute, current)
                                .build(),
                        Set.of("message.read")));
        assertEquals(current, service.findById(pending.getId()).getAttribute(attribute));

        service = new InMemoryOAuth2AuthorizationService(pending);
        provider = provider(client, service, new InMemoryOAuth2AuthorizationConsentService());
        provider.consent(consent(PRINCIPAL, Set.of("message.read")));
        assertNull(service.findById(pending.getId()).getAttribute(attribute));
    }

    @Test
    void passesInFlightAuthorizationAndConsentGrantToAuthorizationCodeGenerator() {
        RegisteredClient registeredClient = registeredClient(Set.of("message.read"));
        OAuth2Authorization authorization = authorization(registeredClient, Set.of("message.read"));
        ConsentSubmission consent = consent(PRINCIPAL, Set.of("message.read"));
        AtomicReference<OAuth2TokenContext> generatedContext = new AtomicReference<>();
        Instant issuedAt = Instant.parse("2026-09-01T01:00:00Z");
        AuthorizationConsentProcessor provider = provider(
                registeredClient,
                new InMemoryOAuth2AuthorizationService(authorization),
                new InMemoryOAuth2AuthorizationConsentService(),
                context -> {
                    generatedContext.set(context);
                    return new OAuth2AuthorizationCode(
                            "custom-authorization-code",
                            issuedAt,
                            issuedAt.plusSeconds(300));
                },
                context -> {
                });

        AuthorizationOutcome.CodeIssued result = provider.consent(consent);

        assertEquals("custom-authorization-code", result.code().getTokenValue());
        assertSame(authorization, generatedContext.get().getAuthorization());
        assertSame(consent, generatedContext.get().getAuthorizationGrant());
        assertEquals(Set.of("message.read"), generatedContext.get().getAuthorizedScopes());
    }

    @Test
    void generatorFailureLeavesNoRedeemableAuthorizationCode() {
        RegisteredClient client = registeredClient(Set.of("message.read"));
        OAuth2Authorization pending = authorization(client, Set.of("message.read"));
        InMemoryOAuth2AuthorizationService authorizations = new InMemoryOAuth2AuthorizationService(pending);
        var provider = provider(
                client,
                authorizations,
                new InMemoryOAuth2AuthorizationConsentService(),
                context -> null,
                context -> {
                });

        var error = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.consent(consent(PRINCIPAL, Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, error.getError().getErrorCode());
        assertNull(authorizations.findById(pending.getId()).getAuthorizationCode());
    }

    private static AuthorizationConsentProcessor provider(
            RegisteredClient registeredClient,
            InMemoryOAuth2AuthorizationService authorizationService,
            InMemoryOAuth2AuthorizationConsentService authorizationConsentService) {
        return provider(
                registeredClient,
                authorizationService,
                authorizationConsentService,
                new DefaultAuthorizationCodeGenerator(),
                context -> {
                });
    }

    private static AuthorizationConsentProcessor provider(
            RegisteredClient registeredClient,
            InMemoryOAuth2AuthorizationService authorizationService,
            InMemoryOAuth2AuthorizationConsentService authorizationConsentService,
            AuthorizationCodeGenerator generator,
            AuthorizationConsentCustomizer customizer) {
        return new AuthorizationConsentProcessor(
                new InMemoryRegisteredClientRepository(registeredClient),
                authorizationService,
                authorizationConsentService,
                new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                generator,
                java.util.List.of(customizer));
    }

    private static ConsentSubmission consent(SecurityIdentity principal, Set<String> scopes) {
        return new ConsentSubmission(
                "https://issuer.example.com/oauth2/authorize",
                "messaging-client",
                principal,
                INTERNAL_STATE,
                scopes,
                Map.of());
    }

    private static OAuth2Authorization authorization(
            RegisteredClient registeredClient, Set<String> requestedScopes) {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://issuer.example.com/oauth2/authorize")
                .clientId(registeredClient.getClientId())
                .redirectUri("https://client.example.com/callback")
                .scopes(requestedScopes)
                .state("client-state")
                .build();
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2ParameterNames.STATE, INTERNAL_STATE)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .build();
    }

    private static RegisteredClient registeredClient(Set<String> scopes) {
        RegisteredClient.Builder builder = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback");
        scopes.forEach(builder::scope);
        return builder.build();
    }

    private static SecurityIdentity identity(String principalName) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(principalName))
                .build();
    }
}
