package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceAuthorizationRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class DeviceAuthorizationServiceTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example").build();

    @Test
    void generatesAndSavesCodesWithPerClientTtlWithoutApprovingScopes() {
        RegisteredClient registeredClient = deviceClient(Duration.ofMinutes(2));
        RecordingAuthorizationService authorizationService = new RecordingAuthorizationService();
        DeviceAuthorizationService provider = new DeviceAuthorizationService(
                authorizationService,
                new DefaultAuthorizationServerContext(SETTINGS),
                new OAuth2DeviceCodeGenerator(),
                new OAuth2UserCodeGenerator());
        SecurityIdentity clientPrincipal = clientIdentity(registeredClient);
        DeviceAuthorizationRequest authentication = new DeviceAuthorizationRequest(
                clientPrincipal, Set.of("message.read"), Map.of("custom", "value"));

        DeviceCodesIssued result = provider.authorize(authentication);

        assertEquals(128, result.deviceCode().getTokenValue().length());
        assertTrue(result.deviceCode().getTokenValue().matches("[A-Za-z0-9_-]{128}"));
        assertTrue(
                result.userCode()
                        .getTokenValue()
                        .matches("[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}"));
        assertEquals(
                Duration.ofMinutes(2),
                Duration.between(
                        result.deviceCode().getIssuedAt(), result.deviceCode().getExpiresAt()));
        assertEquals(
                Duration.ofMinutes(2),
                Duration.between(
                        result.userCode().getIssuedAt(), result.userCode().getExpiresAt()));

        OAuth2Authorization saved = authorizationService.saved;
        assertNotNull(saved);
        assertEquals(registeredClient.getId(), saved.getRegisteredClientId());
        assertEquals(registeredClient.getClientId(), saved.getPrincipalName());
        assertEquals(AuthorizationGrantType.DEVICE_CODE, saved.getAuthorizationGrantType());
        assertEquals(Set.of("message.read"), saved.getAttribute(OAuth2ParameterNames.SCOPE));
        assertTrue(saved.getAuthorizedScopes().isEmpty());
        assertNull(saved.getAttribute(SecurityIdentity.class.getName()));
        assertSame(result.deviceCode(), saved.getToken(OAuth2DeviceCode.class).getToken());
        assertSame(result.userCode(), saved.getToken(OAuth2UserCode.class).getToken());
        assertFalse(saved.getToken(OAuth2DeviceCode.class).isInvalidated());
        assertFalse(saved.getToken(OAuth2UserCode.class).isInvalidated());
        assertEquals(1, authorizationService.saveInvocations);
    }

    @Test
    void usesFiveMinuteDefaultTtl() {
        RegisteredClient registeredClient = deviceClient(null);
        RecordingAuthorizationService authorizationService = new RecordingAuthorizationService();
        DeviceAuthorizationService provider = new DeviceAuthorizationService(
                authorizationService,
                new DefaultAuthorizationServerContext(SETTINGS),
                new OAuth2DeviceCodeGenerator(),
                new OAuth2UserCodeGenerator());

        DeviceCodesIssued result = provider.authorize(request(registeredClient, Set.of()));

        assertEquals(
                Duration.ofMinutes(5),
                Duration.between(
                        result.deviceCode().getIssuedAt(), result.deviceCode().getExpiresAt()));
    }

    @Test
    void rejectsUnauthorizedClientScopeAndUnauthenticatedIdentity() {
        RegisteredClient unauthorized = RegisteredClient.withId("password-registration")
                .clientId("password-client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .build();
        assertError(request(unauthorized, Set.of()), OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        assertError(
                request(deviceClient(null), Set.of("message.admin")),
                OAuth2ErrorCodes.INVALID_SCOPE);

        SecurityIdentity user = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .build();
        DeviceAuthorizationRequest request = new DeviceAuthorizationRequest(user, Set.of(), Map.of());
        assertError(request, OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Test
    void generatorFailureDoesNotSavePartialAuthorization() {
        RegisteredClient registeredClient = deviceClient(null);
        RecordingAuthorizationService authorizationService = new RecordingAuthorizationService();
        Instant issuedAt = Instant.parse("2026-09-04T01:00:00Z");

        var missingDeviceCode = new DeviceAuthorizationService(
                authorizationService,
                new DefaultAuthorizationServerContext(SETTINGS),
                context -> null,
                new OAuth2UserCodeGenerator());
        assertError(
                missingDeviceCode,
                request(registeredClient, Set.of()),
                OAuth2ErrorCodes.SERVER_ERROR);
        assertEquals(0, authorizationService.saveInvocations);

        var missingUserCode = new DeviceAuthorizationService(
                authorizationService,
                new DefaultAuthorizationServerContext(SETTINGS),
                context -> new OAuth2DeviceCode(
                        "device-code", issuedAt, issuedAt.plusSeconds(300)),
                context -> null);
        assertError(
                missingUserCode,
                request(registeredClient, Set.of()),
                OAuth2ErrorCodes.SERVER_ERROR);
        assertEquals(0, authorizationService.saveInvocations);
    }

    private static void assertError(DeviceAuthorizationRequest authentication, String errorCode) {
        assertError(
                new DeviceAuthorizationService(
                        new RecordingAuthorizationService(),
                        new DefaultAuthorizationServerContext(SETTINGS),
                        new OAuth2DeviceCodeGenerator(),
                        new OAuth2UserCodeGenerator()),
                authentication,
                errorCode);
    }

    private static void assertError(
            DeviceAuthorizationService provider,
            DeviceAuthorizationRequest authentication,
            String errorCode) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.authorize(authentication));
        assertEquals(errorCode, exception.getError().getErrorCode());
    }

    private static DeviceAuthorizationRequest request(
            RegisteredClient registeredClient, Set<String> scopes) {
        return new DeviceAuthorizationRequest(clientIdentity(registeredClient), scopes, Map.of());
    }

    private static SecurityIdentity clientIdentity(RegisteredClient registeredClient) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        registeredClient)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        ClientAuthenticationMethod.NONE)
                .build();
    }

    private static RegisteredClient deviceClient(Duration ttl) {
        RegisteredClient.Builder builder = RegisteredClient.withId("device-registration")
                .clientId("device-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .scope("message.read");
        if (ttl != null) {
            builder.tokenSettings(TokenSettings.builder().deviceCodeTimeToLive(ttl).build());
        }
        return builder.build();
    }

    private static final class RecordingAuthorizationService implements OAuth2AuthorizationService {

        private OAuth2Authorization saved;
        private int saveInvocations;

        @Override
        public void save(OAuth2Authorization authorization) {
            this.saveInvocations++;
            this.saved = authorization;
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return this.saved != null && this.saved.getId().equals(id) ? this.saved : null;
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return this.saved != null && this.saved.getToken(token) != null ? this.saved : null;
        }
    }
}
