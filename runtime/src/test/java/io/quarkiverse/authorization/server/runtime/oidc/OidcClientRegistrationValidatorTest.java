package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationContext;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequest;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.runtime.client.registration.DefaultClientRegistrationScopeValidator;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OidcClientRegistrationValidatorTest {
    private final OidcClientRegistrationValidator validator = new OidcClientRegistrationValidator(
            new DefaultClientRegistrationScopeValidator());

    @ParameterizedTest
    @ValueSource(strings = {
            "//rp.example/path",
            "/relative",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,hello",
            "vbscript:msgbox(1)",
            "https://rp.example/callback#fragment",
            "https://rp.example/a b"
    })
    void rejectsUnsafeRedirectAndPostLogoutUris(String uri) {
        assertError(
                "invalid_redirect_uri",
                context(OidcClientRegistration.builder().redirectUri(uri).build()));
        assertError(
                "invalid_client_metadata",
                context(
                        OidcClientRegistration.builder()
                                .redirectUri("https://rp.example/callback")
                                .postLogoutRedirectUri(uri)
                                .build()));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://rp.example/callback",
            "http://127.0.0.1/callback",
            "myapp:/callback"
    })
    void permitsAbsoluteUrisWithSafeSchemes(String uri) {
        assertDoesNotThrow(
                () -> this.validator.validate(
                        context(
                                OidcClientRegistration.builder()
                                        .redirectUri(uri)
                                        .postLogoutRedirectUri(uri)
                                        .build())));
    }

    @Test
    void scopesRequireAnExplicitApplicationPolicy() {
        assertError(
                "invalid_scope",
                context(
                        OidcClientRegistration.builder()
                                .redirectUri("https://rp.example/callback")
                                .scope("openid")
                                .build()));
        assertDoesNotThrow(
                () -> this.validator.validate(
                        context(
                                OidcClientRegistration.builder()
                                        .redirectUri("https://rp.example/callback")
                                        .build())));
    }

    @Test
    void publicJwkValidatorRequiresHttpsButDoesNotEnableServerJwksSupport() {
        assertError(
                "invalid_client_metadata",
                context(
                        OidcClientRegistration.builder()
                                .redirectUri("https://rp.example/callback")
                                .jwkSetUrl("http://rp.example/jwks")
                                .build()));
        assertDoesNotThrow(
                () -> this.validator.validate(
                        context(
                                OidcClientRegistration.builder()
                                        .redirectUri("https://rp.example/callback")
                                        .jwkSetUrl("https://rp.example/jwks")
                                        .build())));
    }

    private void assertError(String code, OidcClientRegistrationContext context) {
        assertEquals(
                code,
                assertThrows(
                        OAuth2AuthenticationException.class,
                        () -> this.validator.validate(context))
                        .getError()
                        .getErrorCode());
    }

    private static OidcClientRegistrationContext context(OidcClientRegistration registration) {
        return new OidcClientRegistrationContext(
                new OidcClientRegistrationRequest(
                        QuarkusSecurityIdentity.builder().setAnonymous(true).build(),
                        registration));
    }
}
