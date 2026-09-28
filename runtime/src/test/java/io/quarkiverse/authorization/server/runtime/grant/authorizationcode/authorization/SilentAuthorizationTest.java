package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.config.TestOidcConfig;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class SilentAuthorizationTest {
    private static final String CALLBACK = "https://client.example/callback";
    private static final RegisteredClient CLIENT = RegisteredClient.withId("client").clientId("client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(CALLBACK)
            .scope("openid").scope("message.read")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build();
    private final InMemoryOAuth2AuthorizationConsentService consents = new InMemoryOAuth2AuthorizationConsentService();

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void silentErrorsDoNotWriteAuthorizationOrGenerateCodes(boolean anonymous) {
        AtomicBoolean validated = new AtomicBoolean();
        var processor = this.processor(new DefaultAuthorizationConsentPolicy(), context -> validated.set(true));
        var exception = assertThrows(AuthorizationRequestException.class, () -> processor.authorize(
                SilentAuthorizationTest.request(anonymous, CALLBACK, "none", Set.of("openid", "message.read"))));
        assertEquals(anonymous ? "login_required" : "consent_required", exception.getError().getErrorCode());
        assertEquals(CALLBACK, exception.getRedirect().uri());
        assertEquals("client-state", exception.getRedirect().state());
        assertTrue(validated.get());
        assertNull(this.consents.findById("client", "user"));
    }

    @Test
    void silentRequestHonorsTheApplicationConsentPolicy() {
        var processor = this.processor(context -> true, context -> {
        });
        // Normally openid alone does not need consent, but a host policy can require it.
        var exception = assertThrows(AuthorizationRequestException.class, () -> processor.authorize(
                SilentAuthorizationTest.request(false, CALLBACK, "none", Set.of("openid"))));
        assertEquals("consent_required", exception.getError().getErrorCode());
    }

    @Test
    void untrustedRedirectAndInvalidScopesWinOverSilentLoginErrors() {
        var processor = this.processor(new DefaultAuthorizationConsentPolicy(), context -> {
        });
        var redirect = assertThrows(AuthorizationRequestException.class, () -> processor.authorize(
                SilentAuthorizationTest.request(true, "https://attacker.example", "none login", Set.of("openid"))));
        assertEquals("invalid_request", redirect.getError().getErrorCode());
        assertNull(redirect.getRedirect());
        var scope = assertThrows(AuthorizationRequestException.class, () -> processor.authorize(
                SilentAuthorizationTest.request(true, CALLBACK, "none", Set.of("openid", "unregistered"))));
        assertEquals("invalid_scope", scope.getError().getErrorCode());
    }

    @Test
    void validatesPromptTypeAndCombinationsEvenForDirectProtocolCalls() {
        var processor = this.processor(new DefaultAuthorizationConsentPolicy(), context -> {
        });
        for (Object value : List.of(new String[] { "none", "none" }, 42, "", " ", "none login", "none unknown")) {
            var exception = assertThrows(AuthorizationRequestException.class, () -> processor.authorize(
                    SilentAuthorizationTest.request(true, CALLBACK, value, Set.of("openid"))));
            assertEquals("invalid_request", exception.getError().getErrorCode());
        }
    }

    private AuthorizationRequestProcessor processor(AuthorizationConsentPolicy consentPolicy,
            AuthorizationRequestValidator validator) {
        return new AuthorizationRequestProcessor(new InMemoryRegisteredClientRepository(CLIENT),
                new OAuth2AuthorizationService() {
                    public void save(OAuth2Authorization authorization) {
                        throw new AssertionError("Silent error must not save authorization");
                    }

                    public void remove(OAuth2Authorization authorization) {
                        throw new AssertionError("Silent error must not remove authorization");
                    }

                    public OAuth2Authorization findById(String id) {
                        throw new AssertionError("Unexpected authorization lookup");
                    }

                    public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
                        throw new AssertionError("Unexpected token lookup");
                    }
                }, this.consents,
                new DefaultAuthorizationServerContext(
                        AuthorizationServerSettings.builder().issuer("https://issuer.example").build()),
                new TestOidcConfig(true, false), List.of(validator), consentPolicy,
                context -> {
                    throw new AssertionError("Silent error must not generate a code");
                });
    }

    private static AuthorizationRequest request(boolean anonymous, String redirect, Object prompt, Set<String> scopes) {
        SecurityIdentity identity = QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal("user"))
                .setAnonymous(anonymous).build();
        return new AuthorizationRequest("https://issuer.example/authorize", "client", identity, redirect,
                "client-state", scopes, Map.of("prompt", prompt, "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method", "S256"));
    }
}
