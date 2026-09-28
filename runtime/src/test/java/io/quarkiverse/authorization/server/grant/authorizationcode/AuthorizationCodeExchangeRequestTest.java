package io.quarkiverse.authorization.server.grant.authorizationcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationCodeExchangeRequestTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("messaging-client"))
            .build();

    @Test
    void exposesAuthorizationCodeGrantParameters() {
        AuthorizationCodeExchangeRequest authentication = new AuthorizationCodeExchangeRequest(
                "authorization-code",
                CLIENT_PRINCIPAL,
                "https://client.example.com/callback",
                Map.of("code_verifier", "verifier"));

        assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, authentication.getGrantType());
        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("authorization-code", authentication.getCode());
        assertEquals("https://client.example.com/callback", authentication.getRedirectUri());
        assertEquals(Map.of("code_verifier", "verifier"), authentication.getAdditionalParameters());
    }

    @Test
    void rejectsMissingCodeOrClientPrincipal() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizationCodeExchangeRequest(" ", CLIENT_PRINCIPAL, null, Map.of()));
        assertThrows(
                NullPointerException.class,
                () -> new AuthorizationCodeExchangeRequest(
                        "authorization-code", null, null, Map.of()));
    }
}
