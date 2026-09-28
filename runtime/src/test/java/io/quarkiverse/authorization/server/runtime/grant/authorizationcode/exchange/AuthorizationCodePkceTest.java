package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationCodePkceTest {
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String REDIRECT = "https://client.example/callback";

    @ParameterizedTest
    @ValueSource(strings = { "none", "client_secret_basic", "client_secret_post" })
    void grantVerifiesPkceForEveryClientAuthenticationMethodWithOneAuthorizationLookup(
            String method) {
        var fixture = new Fixture(method, false, CHALLENGE, "S256");
        fixture.exchange(VERIFIER);
        assertEquals(1, fixture.lookups);
        assertEquals(1, fixture.generations);
        assertTrue(fixture.saved().getAuthorizationCode().isInvalidated());
    }

    @ParameterizedTest
    @ValueSource(strings = { "none", "client_secret_basic", "client_secret_post" })
    void invalidProofCannotConsumeCodeOrGenerateTokens(String method) {
        var fixture = new Fixture(method, false, CHALLENGE, "S256");
        for (String invalid : new String[] { null, "wrong-verifier", "x".repeat(43), "x".repeat(129) }) {
            assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> fixture.exchange(invalid));
            assertSame(fixture.original, fixture.saved());
            assertEquals(0, fixture.generations);
        }
        fixture.exchange(VERIFIER);
        assertEquals(1, fixture.generations);
    }

    @Test
    void malformedProgrammaticVerifierCannotBypassHttpParameterValidation() {
        var fixture = new Fixture("none", false, CHALLENGE, "S256");
        for (Object malformed : new Object[] { " ", new String[] { VERIFIER, VERIFIER }, 42 }) {
            assertError(OAuth2ErrorCodes.INVALID_REQUEST, () -> fixture.exchange(malformed));
            assertSame(fixture.original, fixture.saved());
        }
        fixture.exchange(VERIFIER);
    }

    @ParameterizedTest
    @ValueSource(strings = { "none", "client_secret_basic" })
    void wrongVerifierOnRedeemedCodeCannotRevokeIssuedTokens(String method) {
        var fixture = new Fixture(method, false, CHALLENGE, "S256");
        fixture.exchange(VERIFIER);
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> fixture.exchange("wrong-verifier"));
        assertTrue(fixture.saved().getAccessToken().isActive());
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> fixture.exchange(VERIFIER));
        assertTrue(fixture.saved().getAccessToken().isInvalidated());
    }

    @Test
    void confidentialClientCanOmitPkceOnlyWhenNeitherClientNorAuthorizationRequiresIt() {
        new Fixture("client_secret_basic", false, null, null).exchange(null);
        var unexpectedVerifier = new Fixture("client_secret_basic", false, null, null);
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> unexpectedVerifier.exchange(VERIFIER));
        var required = new Fixture("client_secret_basic", true, null, null);
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> required.exchange(null));
    }

    @Test
    void publicClientCannotRedeemCodeWithoutPkceEvenWhenRequireProofKeyIsFalse() {
        var fixture = new Fixture("none", false, null, null);
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> fixture.exchange(null));
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> fixture.exchange(VERIFIER));
        assertEquals(0, fixture.generations);
    }

    @ParameterizedTest
    @ValueSource(strings = { "plain", "unknown" })
    void rejectsUnsupportedStoredChallengeMethod(String method) {
        var fixture = new Fixture("none", false, CHALLENGE, method);
        assertError(OAuth2ErrorCodes.INVALID_GRANT, () -> fixture.exchange(VERIFIER));
        assertSame(fixture.original, fixture.saved());
    }

    private static void assertError(String expected, Runnable action) {
        assertEquals(
                expected,
                assertThrows(OAuth2AuthenticationException.class, action::run)
                        .getError()
                        .getErrorCode());
    }

    private static final class Fixture implements OAuth2AuthorizationService {
        final InMemoryOAuth2AuthorizationService store;
        final OAuth2Authorization original;
        final SecurityIdentity clientIdentity;
        final AuthorizationCodeExchange grant;
        int lookups;
        int generations;

        Fixture(String method, boolean requirePkce, String challenge, String challengeMethod) {
            var authenticationMethod = new ClientAuthenticationMethod(method);
            var client = RegisteredClient.withId("registration")
                    .clientId("client")
                    .clientAuthenticationMethod(authenticationMethod)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT)
                    .scope("message.read")
                    .clientSettings(
                            ClientSettings.builder().requireProofKey(requirePkce).build())
                    .build();
            clientIdentity = QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal("client"))
                    .addAttribute(
                            OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                            client)
                    .addAttribute(
                            OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                            authenticationMethod)
                    .build();
            var authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri("https://issuer.example/oauth2/authorize")
                    .clientId("client")
                    .redirectUri(REDIRECT)
                    .scope("message.read");
            if (challenge != null) {
                authorizationRequest.additionalParameters(
                        Map.of(
                                "code_challenge",
                                challenge,
                                "code_challenge_method",
                                challengeMethod));
            }
            Instant now = Instant.now();
            original = OAuth2Authorization.withRegisteredClient(client)
                    .principalName("owner")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(Set.of("message.read"))
                    .attribute(
                            OAuth2AuthorizationRequest.class.getName(),
                            authorizationRequest.build())
                    .attribute(
                            SecurityIdentity.class.getName(),
                            QuarkusSecurityIdentity.builder()
                                    .setPrincipal(new QuarkusPrincipal("owner"))
                                    .build())
                    .authorizationCode(
                            new OAuth2AuthorizationCode("code", now, now.plusSeconds(300)))
                    .build();
            store = new InMemoryOAuth2AuthorizationService(original);
            grant = new AuthorizationCodeExchange(
                    this,
                    context -> {
                        generations++;
                        return new OAuth2AccessToken(
                                OAuth2AccessToken.TokenType.BEARER,
                                "access-token",
                                now,
                                now.plusSeconds(300),
                                context.getAuthorizedScopes());
                    },
                    new DefaultAuthorizationServerContext(AuthorizationServerSettings.builder()
                            .issuer("https://issuer.example")
                            .build()),
                    DPoPTestSupport.binding());
        }

        void exchange(Object verifier) {
            grant.exchange(
                    new AuthorizationCodeExchangeRequest(
                            "code",
                            clientIdentity,
                            REDIRECT,
                            verifier == null ? Map.of() : Map.of("code_verifier", verifier)));
        }

        OAuth2Authorization saved() {
            return store.findById(original.getId());
        }

        public void save(OAuth2Authorization authorization) {
            store.save(authorization);
        }

        public void remove(OAuth2Authorization authorization) {
            store.remove(authorization);
        }

        public OAuth2Authorization findById(String id) {
            return store.findById(id);
        }

        public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
            lookups++;
            return store.findByToken(token, type);
        }
    }
}
