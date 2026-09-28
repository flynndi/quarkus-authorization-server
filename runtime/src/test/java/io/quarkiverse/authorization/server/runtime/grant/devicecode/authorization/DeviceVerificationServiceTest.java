package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentSubmission;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationOutcome.Approved;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationOutcome.ConfirmationRequired;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class DeviceVerificationServiceTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final String USER_CODE = "BCDF-GHJK";
    private static final String DEVICE_CODE = "device-code";
    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .deviceVerificationEndpoint("/device/activate")
            .build();

    @Test
    void bindsAuthenticatedPrincipalAndReturnsConsent() {
        TestContext test = context(Set.of("message.read", "message.write"), null);
        SecurityIdentity principal = identity("resource-owner", false);

        DeviceVerificationOutcome result = test.verificationProvider.verify(
                new DeviceVerificationRequest(principal, USER_CODE, Map.of()));

        ConfirmationRequired consent = assertInstanceOf(ConfirmationRequired.class, result);
        assertEquals("device-client", consent.clientId());
        assertEquals(USER_CODE, consent.userCode());
        assertEquals(Set.of("message.read", "message.write"), consent.requestedScopes());
        assertTrue(consent.authorizedScopes().isEmpty());
        assertNotNull(consent.state());

        OAuth2Authorization saved = test.authorizations.findByToken(
                consent.state(), DeviceConsentService.STATE_TOKEN_TYPE);
        assertNotNull(saved);
        assertEquals("resource-owner", saved.getPrincipalName());
        assertEquals(
                principal.getRoles(),
                saved.<SecurityIdentity> getAttribute(SecurityIdentity.class.getName()).getRoles());
        assertTrue(saved.getToken(OAuth2UserCode.class).isActive());
    }

    @Test
    void existingScopeConsentStillRequiresConfirmationOfThisDevice() {
        OAuth2AuthorizationConsent existingConsent = OAuth2AuthorizationConsent.withId(client().getId(), "resource-owner")
                .scope("message.read")
                .build();
        TestContext test = context(Set.of("message.read"), existingConsent);

        ConfirmationRequired result = assertInstanceOf(
                ConfirmationRequired.class,
                test.verificationProvider.verify(
                        new DeviceVerificationRequest(
                                identity("resource-owner", false), USER_CODE, Map.of())));

        assertEquals("device-client", result.clientId());
        OAuth2Authorization saved = test.authorizations.findById(test.authorizationId);
        assertEquals(Set.of("message.read"), saved.getAuthorizedScopes());
        assertTrue(saved.getToken(OAuth2UserCode.class).isActive());
        assertTrue(saved.getToken(OAuth2DeviceCode.class).isActive());
        assertEquals(Set.of("message.read"), saved.getAttribute(OAuth2ParameterNames.SCOPE));
        assertEquals(result.state(), saved.getAttribute(OAuth2ParameterNames.STATE));
        assertInstanceOf(
                QuarkusSecurityIdentity.class,
                saved.getAttribute(SecurityIdentity.class.getName()));

        test.consentProvider.consent(
                new DeviceConsentSubmission(
                        result.clientId(),
                        identity("resource-owner", false),
                        result.userCode(),
                        result.state(),
                        true,
                        Set.of(),
                        Map.of()));
        assertFalse(
                test.authorizations
                        .findById(test.authorizationId)
                        .getToken(OAuth2UserCode.class)
                        .isActive());
        assertEquals(existingConsent, test.consents.findById(client().getId(), "resource-owner"));
    }

    @Test
    void decliningDevicePreservesHistoricalConsentAndDoesNotRunCustomizer() {
        OAuth2AuthorizationConsent existing = OAuth2AuthorizationConsent.withId(client().getId(), "resource-owner")
                .scope("message.read")
                .build();
        TestContext test = context(Set.of("message.read"), existing);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired confirmation = consent(test, principal);
        AtomicBoolean customized = new AtomicBoolean();
        DeviceConsentService service = new DeviceConsentService(
                new InMemoryRegisteredClientRepository(client()),
                test.authorizations,
                test.consents,
                java.util.List.of(context -> customized.set(true)));
        DeviceConsentSubmission denial = new DeviceConsentSubmission(
                confirmation.clientId(),
                principal,
                confirmation.userCode(),
                confirmation.state(),
                false,
                Set.of(),
                Map.of());

        assertError(service, denial, OAuth2ErrorCodes.ACCESS_DENIED);
        assertEquals(existing, test.consents.findById(client().getId(), "resource-owner"));
        assertFalse(customized.get());
        OAuth2Authorization denied = test.authorizations.findById(test.authorizationId);
        assertFalse(denied.getToken(OAuth2UserCode.class).isActive());
        assertFalse(denied.getToken(OAuth2DeviceCode.class).isActive());
        assertNull(denied.getAttribute(OAuth2ParameterNames.STATE));
        assertTrue(denied.getAuthorizedScopes().isEmpty());
        assertError(service, denial, OAuth2ErrorCodes.INVALID_REQUEST);
    }

    @Test
    void scopePolicyCanSkipSelectionButCannotApproveTheDevice() {
        TestContext test = context(Set.of("message.read"), null);
        SecurityIdentity principal = identity("resource-owner", false);
        DeviceVerificationService service = new DeviceVerificationService(
                new InMemoryRegisteredClientRepository(client()),
                test.authorizations,
                test.consents,
                context -> false);

        ConfirmationRequired confirmation = service.verify(request(principal));
        assertEquals(Set.of("message.read"), confirmation.authorizedScopes());
        assertTrue(
                test.authorizations
                        .findById(test.authorizationId)
                        .getToken(OAuth2UserCode.class)
                        .isActive());
        assertNull(test.consents.findById(client().getId(), "resource-owner"));

        test.consentProvider.consent(
                new DeviceConsentSubmission(
                        confirmation.clientId(),
                        principal,
                        confirmation.userCode(),
                        confirmation.state(),
                        true,
                        Set.of(),
                        Map.of()));
        assertEquals(
                Set.of("message.read"),
                test.authorizations.findById(test.authorizationId).getAuthorizedScopes());
    }

    @Test
    void emptyScopeRequestStillAllowsExplicitDeviceApproval() {
        TestContext test = context(Set.of(), null);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired confirmation = consent(test, principal);
        test.consentProvider.consent(
                new DeviceConsentSubmission(
                        confirmation.clientId(),
                        principal,
                        confirmation.userCode(),
                        confirmation.state(),
                        true,
                        Set.of(),
                        Map.of()));
        assertFalse(
                test.authorizations
                        .findById(test.authorizationId)
                        .getToken(OAuth2UserCode.class)
                        .isActive());
        assertNull(test.consents.findById(client().getId(), "resource-owner"));
    }

    @Test
    void expiredDeviceCannotBeConfirmedWithAnOtherwiseValidStateAndUserCode() {
        TestContext test = context(Set.of("message.read"), null);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired confirmation = consent(test, principal);
        OAuth2Authorization pending = test.authorizations.findById(test.authorizationId);
        test.authorizations.save(
                OAuth2Authorization.from(pending)
                        .token(
                                new OAuth2DeviceCode(
                                        DEVICE_CODE,
                                        Instant.now().minusSeconds(60),
                                        Instant.now().minusSeconds(1)))
                        .build());
        assertError(
                test.consentProvider,
                new DeviceConsentSubmission(
                        confirmation.clientId(),
                        principal,
                        confirmation.userCode(),
                        confirmation.state(),
                        true,
                        Set.of("message.read"),
                        Map.of()),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertTrue(
                test.authorizations
                        .findById(test.authorizationId)
                        .getToken(OAuth2UserCode.class)
                        .isActive());
    }

    @Test
    void rejectsUnknownExpiredAndReplayedUserCodes() {
        TestContext test = context(Set.of("message.read"), null);
        assertError(
                test.verificationProvider,
                new DeviceVerificationRequest(identity("user", false), "ZZZZ-ZZZZ", Map.of()),
                OAuth2ErrorCodes.INVALID_GRANT);

        OAuth2Authorization expired = authorization(
                client(),
                Instant.now().minusSeconds(600),
                Instant.now().minusSeconds(300),
                false);
        TestContext expiredTest = context(expired, null);
        assertError(
                expiredTest.verificationProvider,
                request(identity("user", false)),
                OAuth2ErrorCodes.INVALID_GRANT);

        OAuth2Authorization replayed = authorization(
                client(),
                Instant.now().minusSeconds(30),
                Instant.now().plusSeconds(300),
                true);
        TestContext replayedTest = context(replayed, null);
        assertError(
                replayedTest.verificationProvider,
                request(identity("user", false)),
                OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    void rejectsUnauthenticatedPrincipal() {
        TestContext test = context(Set.of("message.read"), null);
        assertError(
                test.verificationProvider,
                request(identity("anonymousUser", true)),
                OAuth2ErrorCodes.ACCESS_DENIED);
        OAuth2Authorization unchanged = test.authorizations.findById(test.authorizationId);
        assertEquals("device-client", unchanged.getPrincipalName());
        assertNull(unchanged.getAttribute(SecurityIdentity.class.getName()));
    }

    @Test
    void approvesConsentAndConsumesUserCode() {
        TestContext test = context(Set.of("message.read", "message.write"), null);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired consent = consent(test, principal);

        Approved result = test.consentProvider.consent(
                new DeviceConsentSubmission(
                        consent.clientId(),
                        principal,
                        consent.userCode(),
                        consent.state(),
                        true,
                        Set.of("message.read"),
                        Map.of()));

        OAuth2Authorization approved = test.authorizations.findById(test.authorizationId);
        assertEquals(Set.of("message.read"), approved.getAuthorizedScopes());
        assertFalse(approved.getToken(OAuth2UserCode.class).isActive());
        assertTrue(approved.getToken(OAuth2DeviceCode.class).isActive());
        assertNull(approved.getAttribute(OAuth2ParameterNames.STATE));
        assertNull(approved.getAttribute(OAuth2ParameterNames.SCOPE));
        assertError(
                test.consentProvider,
                new DeviceConsentSubmission(
                        consent.clientId(),
                        principal,
                        consent.userCode(),
                        consent.state(),
                        true,
                        Set.of("message.read"),
                        Map.of()),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertEquals(
                Set.of("message.read"),
                test.consents.findById(client().getId(), "resource-owner").getScopes());
    }

    @Test
    void denialInvalidatesBothCodesAndConsumesState() {
        TestContext test = context(Set.of("message.read"), null);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired consent = consent(test, principal);

        assertError(
                test.consentProvider,
                new DeviceConsentSubmission(
                        consent.clientId(),
                        principal,
                        consent.userCode(),
                        consent.state(),
                        false,
                        Set.of(),
                        Map.of()),
                OAuth2ErrorCodes.ACCESS_DENIED);

        OAuth2Authorization denied = test.authorizations.findById(test.authorizationId);
        assertFalse(denied.getToken(OAuth2UserCode.class).isActive());
        assertFalse(denied.getToken(OAuth2DeviceCode.class).isActive());
        assertNull(denied.getAttribute(OAuth2ParameterNames.STATE));
    }

    @Test
    void consentIsBoundToStatePrincipalClientUserCodeAndRequestedScopes() {
        TestContext test = context(Set.of("message.read"), null);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired consent = consent(test, principal);

        assertConsentError(
                test,
                consent,
                identity("other-user", false),
                consent.clientId(),
                consent.userCode(),
                consent.state(),
                Set.of("message.read"),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertConsentError(
                test,
                consent,
                principal,
                "other-client",
                consent.userCode(),
                consent.state(),
                Set.of("message.read"),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertConsentError(
                test,
                consent,
                principal,
                consent.clientId(),
                "ZZZZ-ZZZZ",
                consent.state(),
                Set.of("message.read"),
                OAuth2ErrorCodes.INVALID_REQUEST);
        assertConsentError(
                test,
                consent,
                principal,
                consent.clientId(),
                consent.userCode(),
                consent.state(),
                Set.of("message.admin"),
                OAuth2ErrorCodes.INVALID_SCOPE);
        assertConsentError(
                test,
                consent,
                principal,
                consent.clientId(),
                consent.userCode(),
                "other-state",
                Set.of("message.read"),
                OAuth2ErrorCodes.INVALID_REQUEST);
    }

    @Test
    void existingConsentIsMergedOnlyForRequestedScopes() {
        OAuth2AuthorizationConsent existing = OAuth2AuthorizationConsent.withId(client().getId(), "resource-owner")
                .scope("message.read")
                .scope("unrelated")
                .build();
        TestContext test = context(Set.of("message.read", "message.write"), existing);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired consent = consent(test, principal);
        assertEquals(Set.of("message.read"), consent.authorizedScopes());

        test.consentProvider.consent(
                new DeviceConsentSubmission(
                        consent.clientId(),
                        principal,
                        consent.userCode(),
                        consent.state(),
                        true,
                        Set.of("message.write"),
                        Map.of()));

        assertEquals(
                Set.of("message.read", "message.write", "unrelated"),
                test.consents.findById(client().getId(), "resource-owner").getScopes());
        assertEquals(
                Set.of("message.read", "message.write"),
                test.authorizations.findById(test.authorizationId).getAuthorizedScopes());
    }

    @Test
    void consentCustomizerReceivesDeviceAuthorizationWithoutCodeRequest() {
        TestContext test = context(Set.of("message.read"), null);
        SecurityIdentity principal = identity("resource-owner", false);
        ConfirmationRequired consent = consent(test, principal);
        AtomicBoolean called = new AtomicBoolean();
        var consentProvider = new DeviceConsentService(
                new InMemoryRegisteredClientRepository(client()),
                test.authorizations,
                test.consents,
                java.util.List.of(
                        context -> {
                            called.set(true);
                            assertEquals(
                                    AuthorizationGrantType.DEVICE_CODE,
                                    context.authorization().getAuthorizationGrantType());
                            assertEquals(USER_CODE, context.request().getUserCode());
                        }));

        consentProvider.consent(
                new DeviceConsentSubmission(
                        consent.clientId(),
                        principal,
                        consent.userCode(),
                        consent.state(),
                        true,
                        Set.of("message.read"),
                        Map.of()));

        assertTrue(called.get());
    }

    private static ConfirmationRequired consent(TestContext test, SecurityIdentity principal) {
        return assertInstanceOf(
                ConfirmationRequired.class, test.verificationProvider.verify(request(principal)));
    }

    private static void assertConsentError(
            TestContext test,
            ConfirmationRequired consent,
            SecurityIdentity principal,
            String clientId,
            String userCode,
            String state,
            Set<String> scopes,
            String errorCode) {
        assertError(
                test.consentProvider,
                new DeviceConsentSubmission(
                        clientId, principal, userCode, state, true, scopes, Map.of()),
                errorCode);
    }

    private static void assertError(
            DeviceVerificationService provider,
            DeviceVerificationRequest authentication,
            String errorCode) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class, () -> provider.verify(authentication));
        assertEquals(errorCode, exception.getError().getErrorCode());
    }

    private static void assertError(
            DeviceConsentService provider,
            DeviceConsentSubmission authentication,
            String errorCode) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.consent(authentication));
        assertEquals(errorCode, exception.getError().getErrorCode());
    }

    private static DeviceVerificationRequest request(SecurityIdentity principal) {
        return new DeviceVerificationRequest(principal, USER_CODE, Map.of());
    }

    private static TestContext context(Set<String> scopes, OAuth2AuthorizationConsent consent) {
        return context(
                authorization(
                        client(),
                        Instant.now().minusSeconds(30),
                        Instant.now().plusSeconds(300),
                        false,
                        scopes),
                consent);
    }

    private static TestContext context(
            OAuth2Authorization authorization, OAuth2AuthorizationConsent consent) {
        RegisteredClient client = client();
        InMemoryOAuth2AuthorizationService authorizations = new InMemoryOAuth2AuthorizationService(authorization);
        InMemoryOAuth2AuthorizationConsentService consents = consent != null
                ? new InMemoryOAuth2AuthorizationConsentService(consent)
                : new InMemoryOAuth2AuthorizationConsentService();
        InMemoryRegisteredClientRepository clients = new InMemoryRegisteredClientRepository(client);
        return new TestContext(
                authorizations,
                consents,
                new DeviceVerificationService(
                        clients, authorizations, consents, new DefaultDeviceConsentPolicy()),
                new DeviceConsentService(
                        clients, authorizations, consents, java.util.List.of(context -> {
                        })),
                authorization.getId());
    }

    private static OAuth2Authorization authorization(
            RegisteredClient client,
            Instant issuedAt,
            Instant expiresAt,
            boolean userCodeInvalidated) {
        return authorization(
                client, issuedAt, expiresAt, userCodeInvalidated, Set.of("message.read"));
    }

    private static OAuth2Authorization authorization(
            RegisteredClient client,
            Instant issuedAt,
            Instant expiresAt,
            boolean userCodeInvalidated,
            Set<String> scopes) {
        return OAuth2Authorization.withRegisteredClient(client)
                .principalName(client.getClientId())
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
                .token(
                        new OAuth2UserCode(USER_CODE, issuedAt, expiresAt),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                userCodeInvalidated))
                .attribute(OAuth2ParameterNames.SCOPE, scopes)
                .build();
    }

    private static RegisteredClient client() {
        return RegisteredClient.withId("device-registration")
                .clientId("device-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .scope("message.read")
                .scope("message.write")
                .build();
    }

    private static SecurityIdentity identity(String name, boolean anonymous) {
        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(name))
                .addRole("user");
        if (anonymous) {
            builder.setAnonymous(true);
        }
        return builder.build();
    }

    private record TestContext(
            InMemoryOAuth2AuthorizationService authorizations,
            InMemoryOAuth2AuthorizationConsentService consents,
            DeviceVerificationService verificationProvider,
            DeviceConsentService consentProvider,
            String authorizationId) {
    }
}
