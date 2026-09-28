package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.endpoint.PkceParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.config.TestOidcConfig;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationRequestProcessorTest {

    private static final TestOidcConfig OIDC_CONFIG = new TestOidcConfig(false, false);

    private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();
    private static final AuthorizationServerSettings AUTHORIZATION_SERVER_SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example.com").build();

    @Test
    void authenticatesValidRequestAndResolvesOmittedRedirectUri() {
        RegisteredClient registeredClient = authorizationCodeClient(Set.of("message.read"));
        AuthorizationRequestProcessor provider = provider(registeredClient);

        AuthorizationOutcome.CodeIssued result = assertInstanceOf(
                AuthorizationOutcome.CodeIssued.class,
                provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                null,
                                Set.of("message.read"))));

        assertNotNull(result.code());
        assertEquals("https://client.example.com/callback", result.redirectUri());
        assertEquals("state", result.state());
        assertEquals(Set.of("message.read"), result.scopes());
    }

    @Test
    void leavesAnonymousPrincipalUnauthenticated() {
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("anonymousUser"))
                .setAnonymous(true)
                .build();
        AuthorizationRequest authentication = request(
                "messaging-client",
                anonymous,
                "https://client.example.com/callback",
                Set.of("message.read"));

        assertInstanceOf(
                AuthorizationOutcome.LoginRequired.class,
                provider(authorizationCodeClient(Set.of("message.read")))
                        .authorize(authentication));
    }

    @Test
    void neverRedirectsUnknownClientError() {
        AuthorizationRequestProcessor provider = provider(authorizationCodeClient(Set.of("message.read")));

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.authorize(
                        request(
                                "unknown-client",
                                PRINCIPAL,
                                "https://attacker.example.com/callback",
                                Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: client_id", exception.getError().getDescription());
        assertNull(exception.getRedirect());
    }

    @Test
    void reportsMissingRedirectUriForClientWithoutRegisteredRedirects() {
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .build();

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider(registeredClient)
                        .authorize(
                                request(
                                        "messaging-client",
                                        PRINCIPAL,
                                        null,
                                        Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: redirect_uri", exception.getError().getDescription());
        assertNull(exception.getRedirect());
    }

    @Test
    void rejectsClientWithoutAuthorizationCodeGrantAfterRedirectValidation() {
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .build();

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider(registeredClient)
                        .authorize(
                                request(
                                        "messaging-client",
                                        PRINCIPAL,
                                        "https://client.example.com/callback",
                                        Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, exception.getError().getErrorCode());
        assertEquals("https://client.example.com/callback", exception.getRedirect().uri());
    }

    @Test
    void rejectsOpenIdScopeWhenOidcIsDisabled() {
        RegisteredClient registeredClient = authorizationCodeClient(Set.of("openid", "message.read"));

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider(registeredClient)
                        .authorize(
                                request(
                                        "messaging-client",
                                        PRINCIPAL,
                                        "https://client.example.com/callback",
                                        Set.of("openid"))));

        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, exception.getError().getErrorCode());
        assertEquals("https://client.example.com/callback", exception.getRedirect().uri());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = { "none", "client_secret_basic" })
    void requiresCodeChallengeByDefaultForPublicAndConfidentialClients(String authenticationMethod) {
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .clientAuthenticationMethod(new ClientAuthenticationMethod(authenticationMethod))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .build();

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider(registeredClient)
                        .authorize(
                                request(
                                        "messaging-client",
                                        PRINCIPAL,
                                        "https://client.example.com/callback",
                                        Set.of("message.read"), Map.of())));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: code_challenge", exception.getError().getDescription());
        assertEquals(PKCE_ERROR_URI, exception.getError().getUri());
        assertEquals("https://client.example.com/callback", exception.getRedirect().uri());
    }

    @Test
    void rejectsMissingOrUnsupportedCodeChallengeMethod() {
        RegisteredClient registeredClient = authorizationCodeClient(Set.of("message.read"));

        for (Map<String, Object> additionalParameters : Set.<Map<String, Object>> of(
                Map.of(PkceParameterNames.CODE_CHALLENGE, CODE_CHALLENGE),
                Map.of(
                        PkceParameterNames.CODE_CHALLENGE,
                        CODE_CHALLENGE,
                        PkceParameterNames.CODE_CHALLENGE_METHOD,
                        "plain"))) {
            AuthorizationRequestException exception = assertThrows(
                    AuthorizationRequestException.class,
                    () -> provider(registeredClient)
                            .authorize(
                                    request(
                                            "messaging-client",
                                            PRINCIPAL,
                                            "https://client.example.com/callback",
                                            Set.of("message.read"),
                                            additionalParameters)));

            assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
            assertEquals(
                    "OAuth 2.0 Parameter: code_challenge_method",
                    exception.getError().getDescription());
            assertEquals(PKCE_ERROR_URI, exception.getError().getUri());
        }
    }

    @Test
    void acceptsS256AndPersistsCodeChallengeWithAuthorizationRequest() {
        RegisteredClient registeredClient = RegisteredClient.from(authorizationCodeClient(Set.of("message.read")))
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
        AuthorizationRequestProcessor provider = new AuthorizationRequestProcessor(
                new InMemoryRegisteredClientRepository(registeredClient),
                authorizationService,
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                OIDC_CONFIG,
                java.util.List.of(new AuthorizationRequestChecks()),
                new DefaultAuthorizationConsentPolicy(),
                new DefaultAuthorizationCodeGenerator());
        Map<String, Object> additionalParameters = Map.of(
                PkceParameterNames.CODE_CHALLENGE,
                CODE_CHALLENGE,
                PkceParameterNames.CODE_CHALLENGE_METHOD,
                "S256");

        AuthorizationOutcome.CodeIssued result = assertInstanceOf(
                AuthorizationOutcome.CodeIssued.class,
                provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                "https://client.example.com/callback",
                                Set.of("message.read"),
                                additionalParameters)));

        OAuth2Authorization authorization = authorizationService.findByToken(
                result.code().getTokenValue(),
                new OAuth2TokenType(OAuth2ParameterNames.CODE));
        assertNotNull(authorization);
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertEquals(
                CODE_CHALLENGE,
                authorizationRequest
                        .getAdditionalParameters()
                        .get(PkceParameterNames.CODE_CHALLENGE));
        assertEquals(
                "S256",
                authorizationRequest
                        .getAdditionalParameters()
                        .get(PkceParameterNames.CODE_CHALLENGE_METHOD));
    }

    @Test
    void supportsAuthorizationRequestValidatorCustomization() {
        AtomicBoolean invoked = new AtomicBoolean();
        AuthorizationRequestProcessor provider = provider(
                authorizationCodeClient(Set.of("message.read")),
                context -> {
                    invoked.set(true);
                    assertEquals(
                            "messaging-client",
                            context.getRegisteredClient().getClientId());
                    assertEquals("messaging-client", context.getRequest().getClientId());
                },
                new DefaultAuthorizationCodeGenerator());

        AuthorizationOutcome.CodeIssued result = assertInstanceOf(
                AuthorizationOutcome.CodeIssued.class,
                provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                "https://client.example.com/callback",
                                Set.of("message.read"))));

        assertTrue(invoked.get());
    }

    @Test
    void returnsConsentAndSavesRecoverableAuthorizationWhenConsentIsRequired() {
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .clientSettings(
                        ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
        AuthorizationRequestProcessor provider = new AuthorizationRequestProcessor(
                new InMemoryRegisteredClientRepository(registeredClient),
                authorizationService,
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                OIDC_CONFIG,
                java.util.List.of(new AuthorizationRequestChecks()),
                new DefaultAuthorizationConsentPolicy(),
                new DefaultAuthorizationCodeGenerator());

        AuthorizationOutcome.ConsentRequired result = assertInstanceOf(
                AuthorizationOutcome.ConsentRequired.class,
                provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                "https://client.example.com/callback",
                                Set.of("message.read"),
                                Map.of(
                                        PkceParameterNames.CODE_CHALLENGE,
                                        CODE_CHALLENGE,
                                        PkceParameterNames.CODE_CHALLENGE_METHOD,
                                        "S256"))));

        assertEquals(Set.of("message.read"), result.requestedScopes());
        assertEquals("messaging-client", result.clientId());
        assertSame(PRINCIPAL, result.principal());
        assertNotEquals("state", result.state());
        assertTrue(result.authorizedScopes().isEmpty());
        OAuth2Authorization authorization = authorizationService.findByToken(
                result.state(), new OAuth2TokenType(OAuth2ParameterNames.STATE));
        assertNotNull(authorization);
        assertEquals("resource-owner", authorization.getPrincipalName());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertEquals("state", authorizationRequest.getState());
        assertEquals(Set.of("message.read"), authorizationRequest.getScopes());
        assertEquals(
                CODE_CHALLENGE,
                authorizationRequest
                        .getAdditionalParameters()
                        .get(PkceParameterNames.CODE_CHALLENGE));
        assertEquals(
                "S256",
                authorizationRequest
                        .getAdditionalParameters()
                        .get(PkceParameterNames.CODE_CHALLENGE_METHOD));
    }

    @Test
    void skipsConsentWhenAllRequestedScopesWerePreviouslyApproved() {
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .clientSettings(
                        ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        OAuth2AuthorizationConsent authorizationConsent = OAuth2AuthorizationConsent
                .withId(registeredClient.getId(), "resource-owner")
                .scope("message.read")
                .build();
        AuthorizationRequestProcessor provider = new AuthorizationRequestProcessor(
                new InMemoryRegisteredClientRepository(registeredClient),
                new InMemoryOAuth2AuthorizationService(),
                new InMemoryOAuth2AuthorizationConsentService(authorizationConsent),
                new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                OIDC_CONFIG,
                java.util.List.of(new AuthorizationRequestChecks()),
                new DefaultAuthorizationConsentPolicy(),
                new DefaultAuthorizationCodeGenerator());

        AuthorizationOutcome.CodeIssued result = assertInstanceOf(
                AuthorizationOutcome.CodeIssued.class,
                provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                "https://client.example.com/callback",
                                Set.of("message.read"))));

        assertNotNull(result.code());
        assertEquals(Set.of("message.read"), result.scopes());
    }

    @Test
    void generatesAndPersistsAuthorizationCodeWithoutConsent() {
        RegisteredClient registeredClient = authorizationCodeClient(Set.of("message.read"));
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
        AuthorizationRequestProcessor provider = new AuthorizationRequestProcessor(
                new InMemoryRegisteredClientRepository(registeredClient),
                authorizationService,
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                OIDC_CONFIG,
                java.util.List.of(new AuthorizationRequestChecks()),
                new DefaultAuthorizationConsentPolicy(),
                new DefaultAuthorizationCodeGenerator());

        AuthorizationOutcome.CodeIssued result = assertInstanceOf(
                AuthorizationOutcome.CodeIssued.class,
                provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                "https://client.example.com/callback",
                                Set.of("message.read"))));

        OAuth2Authorization authorization = authorizationService.findByToken(
                result.code().getTokenValue(),
                new OAuth2TokenType(OAuth2ParameterNames.CODE));
        assertNotNull(authorization);
        assertEquals(Set.of("message.read"), authorization.getAuthorizedScopes());
        assertSame(result.code(), authorization.getAuthorizationCode().getToken());
        OAuth2AuthorizationRequest savedAuthorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertEquals("state", savedAuthorizationRequest.getState());
    }

    @Test
    void reportsServerErrorWhenAuthorizationCodeGeneratorReturnsNull() {
        AuthorizationRequestProcessor provider = provider(
                authorizationCodeClient(Set.of("message.read")),
                new AuthorizationRequestChecks(),
                context -> null);

        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> provider.authorize(
                        request(
                                "messaging-client",
                                PRINCIPAL,
                                "https://client.example.com/callback",
                                Set.of("message.read"))));

        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, exception.getError().getErrorCode());
        assertNull(exception.getRedirect());
    }

    private static AuthorizationRequestProcessor provider(RegisteredClient registeredClient) {
        return provider(
                registeredClient,
                new AuthorizationRequestChecks(),
                new DefaultAuthorizationCodeGenerator());
    }

    private static AuthorizationRequestProcessor provider(
            RegisteredClient registeredClient,
            AuthorizationRequestValidator validator,
            AuthorizationCodeGenerator generator) {
        return new AuthorizationRequestProcessor(
                new InMemoryRegisteredClientRepository(registeredClient),
                new InMemoryOAuth2AuthorizationService(),
                new InMemoryOAuth2AuthorizationConsentService(),
                new DefaultAuthorizationServerContext(AUTHORIZATION_SERVER_SETTINGS),
                OIDC_CONFIG,
                java.util.List.of(validator),
                new DefaultAuthorizationConsentPolicy(),
                generator);
    }

    private static AuthorizationRequest request(
            String clientId, SecurityIdentity principal, String redirectUri, Set<String> scopes) {
        return request(clientId, principal, redirectUri, scopes, Map.of(
                "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method", "S256"));
    }

    private static AuthorizationRequest request(
            String clientId,
            SecurityIdentity principal,
            String redirectUri,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        return new AuthorizationRequest(
                "https://issuer.example.com/oauth2/authorize",
                clientId,
                principal,
                redirectUri,
                "state",
                scopes,
                additionalParameters);
    }

    private static RegisteredClient authorizationCodeClient(Set<String> scopes) {
        RegisteredClient.Builder builder = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback");
        scopes.forEach(builder::scope);
        return builder.build();
    }
}
