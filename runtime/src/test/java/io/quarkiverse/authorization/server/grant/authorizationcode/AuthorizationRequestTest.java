package io.quarkiverse.authorization.server.grant.authorizationcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationOutcome;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationRequestTest {

    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();

    @Test
    void representsAuthorizationRequest() {
        Set<String> scopes = new LinkedHashSet<>(Set.of("message.read"));
        Map<String, Object> additionalParameters = new LinkedHashMap<>(Map.of("code_challenge", "challenge"));

        AuthorizationRequest authentication = new AuthorizationRequest(
                "https://issuer.example.com/oauth2/authorize",
                "messaging-client",
                PRINCIPAL,
                "https://client.example.com/callback",
                "state",
                scopes,
                additionalParameters);

        scopes.add("message.write");
        additionalParameters.put("tenant", "internal");
        assertSame(PRINCIPAL, authentication.getPrincipal());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(
                Map.of("code_challenge", "challenge"), authentication.getAdditionalParameters());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getScopes().add("message.write"));
    }

    @Test
    void representsSuccessfulAuthorizationResponse() {
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "authorization-code", Instant.now(), Instant.now().plusSeconds(300));

        AuthorizationOutcome.CodeIssued issued = new AuthorizationOutcome.CodeIssued(
                authorizationCode,
                "https://client.example.com/callback",
                "state",
                Set.of("message.read"));
        assertSame(authorizationCode, issued.code());
        assertEquals("state", issued.state());
        assertThrows(UnsupportedOperationException.class, () -> issued.scopes().add("other"));
    }
}
