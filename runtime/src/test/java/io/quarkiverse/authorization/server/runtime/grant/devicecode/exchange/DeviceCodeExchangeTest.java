package io.quarkiverse.authorization.server.runtime.grant.devicecode.exchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport;
import io.quarkiverse.authorization.server.runtime.token.OAuth2RefreshTokenGenerator;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class DeviceCodeExchangeTest {

    private static final String DEVICE_CODE = "device-code";
    private static final String USER_CODE = "BCDF-GHJK";
    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example.com").build();

    @Test
    void rejectsUnknownDeviceCodeAndUnauthenticatedClient() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);
        RecordingAuthorizationService service = new RecordingAuthorizationService();
        RecordingTokenGenerator generator = new RecordingTokenGenerator();
        DeviceCodeExchange provider = provider(service, generator);

        assertError(
                provider,
                authentication(clientIdentity(client), DEVICE_CODE),
                OAuth2ErrorCodes.INVALID_GRANT);
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder()
                .setAnonymous(true)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client)
                .build();
        assertError(
                provider, authentication(anonymous, DEVICE_CODE), OAuth2ErrorCodes.INVALID_CLIENT);
        assertEquals(0, service.saveInvocations);
        assertEquals(0, generator.contexts.size());
    }

    @Test
    void invalidatesDeviceCodeUsedByAnotherClient() {
        RegisteredClient owner = client("owner", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        RegisteredClient attacker = client("attacker", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        RecordingAuthorizationService service = service(pending(owner, false));
        RecordingTokenGenerator generator = new RecordingTokenGenerator();

        assertError(
                provider(service, generator),
                authentication(clientIdentity(attacker), DEVICE_CODE),
                OAuth2ErrorCodes.INVALID_GRANT);

        assertTrue(service.byDeviceCode().getToken(OAuth2DeviceCode.class).isInvalidated());
        assertEquals(1, service.saveInvocations);
        assertTrue(generator.contexts.isEmpty());
    }

    @Test
    void returnsAuthorizationPendingBeforeUserApproval() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        RecordingAuthorizationService service = service(pending(client, false));
        RecordingTokenGenerator generator = new RecordingTokenGenerator();

        OAuth2AuthenticationException error = assertError(
                provider(service, generator),
                authentication(clientIdentity(client), DEVICE_CODE),
                DeviceCodeExchange.AUTHORIZATION_PENDING);

        assertEquals(
                "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5",
                error.getError().getUri());
        assertFalse(service.byDeviceCode().getToken(OAuth2DeviceCode.class).isInvalidated());
        assertEquals(0, service.saveInvocations);
        assertTrue(generator.contexts.isEmpty());
    }

    @Test
    void returnsExpiredTokenAndPersistsInvalidationForPendingAndApprovedRequests() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        for (OAuth2Authorization expired : List.of(pending(client, true), approved(client, true))) {
            RecordingAuthorizationService service = service(expired);
            RecordingTokenGenerator generator = new RecordingTokenGenerator();

            assertError(
                    provider(service, generator),
                    authentication(clientIdentity(client), DEVICE_CODE),
                    DeviceCodeExchange.EXPIRED_TOKEN);

            assertTrue(service.byDeviceCode().getToken(OAuth2DeviceCode.class).isInvalidated());
            assertEquals(1, service.saveInvocations);
            assertTrue(generator.contexts.isEmpty());
        }
    }

    @Test
    void returnsAccessDeniedForRejectedAndConsumedDeviceCodes() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        for (OAuth2Authorization authorization : List.of(denied(client), consumed(client))) {
            RecordingAuthorizationService service = service(authorization);
            RecordingTokenGenerator generator = new RecordingTokenGenerator();

            assertError(
                    provider(service, generator),
                    authentication(clientIdentity(client), DEVICE_CODE),
                    OAuth2ErrorCodes.ACCESS_DENIED);

            assertEquals(0, service.saveInvocations);
            assertTrue(generator.contexts.isEmpty());
        }
    }

    @Test
    void issuesAccessAndRefreshTokensAndPersistsClaims() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);
        OAuth2Authorization approved = approved(client, false);
        RecordingAuthorizationService service = service(approved);
        RecordingTokenGenerator generator = new RecordingTokenGenerator();
        SecurityIdentity clientPrincipal = clientIdentity(client);
        DeviceCodeExchangeRequest authentication = authentication(clientPrincipal, DEVICE_CODE);

        TokenIssuanceResult result = provider(service, generator).exchange(authentication);

        assertSame(clientPrincipal, result.getPrincipal());
        assertSame(client, result.getRegisteredClient());
        assertEquals("access-token", result.getAccessToken().getTokenValue());
        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
        assertEquals("refresh-token", result.getRefreshToken().getTokenValue());
        assertTrue(result.getAdditionalParameters().isEmpty());

        OAuth2Authorization saved = service.byDeviceCode();
        assertTrue(saved.getToken(OAuth2DeviceCode.class).isInvalidated());
        assertTrue(saved.getToken(OAuth2UserCode.class).isInvalidated());
        assertEquals(result.getAccessToken(), saved.getAccessToken().getToken());
        assertEquals(generator.accessToken.getClaims(), saved.getAccessToken().getClaims());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                saved.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertEquals(result.getRefreshToken(), saved.getRefreshToken().getToken());
        assertNull(saved.getToken(OidcIdToken.class));
        assertEquals(1, service.saveInvocations);
        assertEquals(
                List.of(OAuth2TokenType.ACCESS_TOKEN, OAuth2TokenType.REFRESH_TOKEN),
                generator.contexts.stream().map(OAuth2TokenContext::getTokenType).toList());
        for (OAuth2TokenContext context : generator.contexts) {
            assertSame(client, context.getRegisteredClient());
            assertEquals("resource-owner", context.getPrincipal().getPrincipal().getName());
            assertSame(approved, context.getAuthorization());
            assertSame(authentication, context.getAuthorizationGrant());
            assertEquals(AuthorizationGrantType.DEVICE_CODE, context.getAuthorizationGrantType());
            assertEquals(Set.of("message.read"), context.getAuthorizedScopes());
        }
    }

    @Test
    void doesNotIssueRefreshTokenUnlessClientDeclaresRefreshGrant() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        RecordingAuthorizationService service = service(approved(client, false));
        RecordingTokenGenerator generator = new RecordingTokenGenerator();

        TokenIssuanceResult result = provider(service, generator)
                .exchange(authentication(clientIdentity(client), DEVICE_CODE));

        assertNull(result.getRefreshToken());
        assertNull(service.byDeviceCode().getRefreshToken());
        assertEquals(1, generator.contexts.size());
    }

    @Test
    void publicDeviceClientWithoutProofReceivesOnlyAccessToken() {
        RegisteredClient client = client("public-device", ClientAuthenticationMethod.NONE, true);
        RecordingAuthorizationService service = service(approved(client, false));
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        OAuth2TokenGenerator<OAuth2Token> generator = context -> {
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return refreshTokenGenerator.generate(context);
            }
            Instant issuedAt = Instant.now();
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "public-access-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    context.getAuthorizedScopes());
        };

        TokenIssuanceResult result = provider(service, generator)
                .exchange(authentication(clientIdentity(client), DEVICE_CODE));

        assertNull(result.getRefreshToken());
        assertNull(service.byDeviceCode().getRefreshToken());
    }

    @Test
    void customGeneratorCannotIssueUnboundPublicRefreshOrConsumeDeviceOnFailure() {
        RegisteredClient client = client("public-device", ClientAuthenticationMethod.NONE, true);
        RecordingAuthorizationService service = service(approved(client, false));
        assertError(
                provider(service, new RecordingTokenGenerator()),
                authentication(clientIdentity(client), DEVICE_CODE),
                OAuth2ErrorCodes.SERVER_ERROR);
        assertEquals(0, service.saveInvocations);
        assertFalse(service.byDeviceCode().getToken(OAuth2DeviceCode.class).isInvalidated());
        assertNull(service.byDeviceCode().getAccessToken());
        assertNull(service.byDeviceCode().getRefreshToken());
    }

    @Test
    void sequentialReplayDoesNotGenerateAnotherToken() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);
        RecordingAuthorizationService service = service(approved(client, false));
        RecordingTokenGenerator generator = new RecordingTokenGenerator();
        DeviceCodeExchange provider = provider(service, generator);
        DeviceCodeExchangeRequest authentication = authentication(clientIdentity(client), DEVICE_CODE);

        provider.exchange(authentication);
        assertError(provider, authentication, OAuth2ErrorCodes.ACCESS_DENIED);

        assertEquals(2, generator.contexts.size());
        assertEquals(1, service.saveInvocations);
    }

    @Test
    void generationAndSaveFailuresDoNotReturnSuccessOrConsumeStoredDeviceCode() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);
        DeviceCodeExchangeRequest authentication = authentication(clientIdentity(client), DEVICE_CODE);

        RecordingAuthorizationService accessFailureService = service(approved(client, false));
        assertError(
                provider(accessFailureService, context -> null),
                authentication,
                OAuth2ErrorCodes.SERVER_ERROR);
        assertEquals(0, accessFailureService.saveInvocations);
        assertFalse(
                accessFailureService
                        .byDeviceCode()
                        .getToken(OAuth2DeviceCode.class)
                        .isInvalidated());

        RecordingAuthorizationService refreshFailureService = service(approved(client, false));
        OAuth2TokenGenerator<OAuth2Token> refreshFailure = context -> OAuth2TokenType.ACCESS_TOKEN
                .equals(context.getTokenType())
                        ? accessToken("generated-access")
                        : null;
        OAuth2AuthenticationException refreshError = assertError(
                provider(refreshFailureService, refreshFailure),
                authentication,
                OAuth2ErrorCodes.SERVER_ERROR);
        assertEquals(
                "The token generator failed to generate the refresh token.",
                refreshError.getError().getDescription());
        assertEquals(0, refreshFailureService.saveInvocations);
        assertFalse(
                refreshFailureService
                        .byDeviceCode()
                        .getToken(OAuth2DeviceCode.class)
                        .isInvalidated());

        RecordingAuthorizationService wrongRefreshTypeService = service(approved(client, false));
        OAuth2TokenGenerator<OAuth2Token> wrongRefreshType = context -> accessToken("generated-access");
        assertError(
                provider(wrongRefreshTypeService, wrongRefreshType),
                authentication,
                OAuth2ErrorCodes.SERVER_ERROR);
        assertEquals(0, wrongRefreshTypeService.saveInvocations);
        assertFalse(
                wrongRefreshTypeService
                        .byDeviceCode()
                        .getToken(OAuth2DeviceCode.class)
                        .isInvalidated());

        RecordingAuthorizationService saveFailureService = service(approved(client, false));
        saveFailureService.failure = new IllegalStateException("save failed");
        IllegalStateException failure = assertThrows(
                IllegalStateException.class,
                () -> provider(saveFailureService, new RecordingTokenGenerator())
                        .exchange(authentication));
        assertSame(saveFailureService.failure, failure);
        assertEquals(1, saveFailureService.saveInvocations);
        assertFalse(
                saveFailureService.byDeviceCode().getToken(OAuth2DeviceCode.class).isInvalidated());
        assertNull(saveFailureService.byDeviceCode().getAccessToken());
    }

    @Test
    void rejectsApprovedStateWithoutResourceOwnerSnapshot() {
        RegisteredClient client = client("device-client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false);
        OAuth2Authorization malformed = OAuth2Authorization.from(approved(client, false))
                .attributes(
                        attributes -> attributes.remove(SecurityIdentity.class.getName()))
                .build();
        RecordingAuthorizationService service = service(malformed);

        assertError(
                provider(service, new RecordingTokenGenerator()),
                authentication(clientIdentity(client), DEVICE_CODE),
                OAuth2ErrorCodes.INVALID_GRANT);
        assertEquals(0, service.saveInvocations);
    }

    @Test
    void requiresDependenciesAndAuthentication() {
        RecordingAuthorizationService service = new RecordingAuthorizationService();
        RecordingTokenGenerator generator = new RecordingTokenGenerator();
        assertThrows(
                NullPointerException.class,
                () -> new DeviceCodeExchange(null, generator, new DefaultAuthorizationServerContext(SETTINGS),
                        DPoPTestSupport.binding()));
        assertThrows(
                NullPointerException.class,
                () -> new DeviceCodeExchange(service, null, new DefaultAuthorizationServerContext(SETTINGS),
                        DPoPTestSupport.binding()));
        assertThrows(
                NullPointerException.class,
                () -> new DeviceCodeExchange(service, generator, null, DPoPTestSupport.binding()));
        assertThrows(NullPointerException.class, () -> provider(service, generator).exchange(null));
    }

    private static DeviceCodeExchange provider(
            OAuth2AuthorizationService service,
            OAuth2TokenGenerator<? extends OAuth2Token> generator) {
        return new DeviceCodeExchange(service, generator, new DefaultAuthorizationServerContext(SETTINGS),
                DPoPTestSupport.binding());
    }

    private static OAuth2AuthenticationException assertError(
            DeviceCodeExchange provider,
            DeviceCodeExchangeRequest authentication,
            String expectedError) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(authentication));
        assertEquals(expectedError, exception.getError().getErrorCode());
        return exception;
    }

    private static DeviceCodeExchangeRequest authentication(
            SecurityIdentity clientPrincipal, String deviceCode) {
        return new DeviceCodeExchangeRequest(deviceCode, clientPrincipal, Map.of());
    }

    private static SecurityIdentity clientIdentity(RegisteredClient client) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(client.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        client.getClientAuthenticationMethods().iterator().next())
                .build();
    }

    private static RegisteredClient client(
            String clientId, ClientAuthenticationMethod method, boolean refreshTokenGrant) {
        RegisteredClient.Builder builder = RegisteredClient.withId(clientId + "-registration")
                .clientId(clientId)
                .clientAuthenticationMethod(method)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .scope("message.read");
        if (refreshTokenGrant) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        return builder.build();
    }

    private static OAuth2Authorization pending(RegisteredClient client, boolean expired) {
        return authorization(client, expired, false, false, false);
    }

    private static OAuth2Authorization approved(RegisteredClient client, boolean expired) {
        return authorization(client, expired, true, false, false);
    }

    private static OAuth2Authorization denied(RegisteredClient client) {
        return authorization(client, false, true, true, false);
    }

    private static OAuth2Authorization consumed(RegisteredClient client) {
        return authorization(client, false, true, true, true);
    }

    private static OAuth2Authorization authorization(
            RegisteredClient client,
            boolean expired,
            boolean userCodeInvalidated,
            boolean deviceCodeInvalidated,
            boolean accessToken) {
        Instant issuedAt = expired ? Instant.now().minusSeconds(600) : Instant.now().minusSeconds(30);
        Instant expiresAt = expired ? Instant.now().minusSeconds(300) : Instant.now().plusSeconds(300);
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .principalName(
                        userCodeInvalidated ? "resource-owner" : client.getClientId())
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizedScopes(userCodeInvalidated ? Set.of("message.read") : Set.of())
                .token(
                        new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                deviceCodeInvalidated))
                .token(
                        new OAuth2UserCode(USER_CODE, issuedAt, expiresAt),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                userCodeInvalidated));
        if (userCodeInvalidated && !deviceCodeInvalidated) {
            builder.attribute(
                    SecurityIdentity.class.getName(),
                    QuarkusSecurityIdentity.builder()
                            .setPrincipal(new QuarkusPrincipal("resource-owner"))
                            .addRoles(Set.of("user"))
                            .build());
        }
        if (accessToken) {
            builder.accessToken(accessToken("previous-access"));
        }
        return builder.build();
    }

    private static OAuth2AccessToken accessToken(String value) {
        Instant issuedAt = Instant.now();
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                value,
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read"));
    }

    private static RecordingAuthorizationService service(OAuth2Authorization authorization) {
        return new RecordingAuthorizationService(authorization);
    }

    private static final class RecordingTokenGenerator
            implements OAuth2TokenGenerator<OAuth2Token> {

        private final List<OAuth2TokenContext> contexts = new ArrayList<>();
        private Jwt accessToken;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            this.contexts.add(context);
            Instant issuedAt = Instant.now();
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return new OAuth2RefreshToken(
                        "refresh-token", issuedAt, issuedAt.plusSeconds(3600));
            }
            this.accessToken = new Jwt(
                    "access-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    Map.of("alg", "RS256"),
                    Map.of(
                            "sub",
                            context.getPrincipal().getPrincipal().getName(),
                            "scope",
                            context.getAuthorizedScopes()));
            return this.accessToken;
        }
    }

    private static final class RecordingAuthorizationService implements OAuth2AuthorizationService {

        private final InMemoryOAuth2AuthorizationService delegate;
        private int saveInvocations;
        private RuntimeException failure;

        private RecordingAuthorizationService(OAuth2Authorization... authorizations) {
            this.delegate = new InMemoryOAuth2AuthorizationService(authorizations);
        }

        @Override
        public void save(OAuth2Authorization authorization) {
            this.saveInvocations++;
            if (this.failure != null) {
                throw this.failure;
            }
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
            return this.delegate.findByToken(token, tokenType);
        }

        private OAuth2Authorization byDeviceCode() {
            return this.delegate.findByToken(
                    DEVICE_CODE, DeviceCodeExchange.DEVICE_CODE_TOKEN_TYPE);
        }
    }
}
