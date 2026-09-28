package io.quarkiverse.authorization.server.grant.refreshtoken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class RefreshTokenRequestTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("messaging-client"))
            .build();

    @Test
    void exposesRefreshTokenGrantParameters() {
        RefreshTokenRequest authentication = new RefreshTokenRequest(
                "refresh-token",
                CLIENT_PRINCIPAL,
                Set.of("message.read"),
                Map.of("resource", "messages"));

        assertEquals(AuthorizationGrantType.REFRESH_TOKEN, authentication.getGrantType());
        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("refresh-token", authentication.getRefreshToken());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(Map.of("resource", "messages"), authentication.getAdditionalParameters());
    }

    @Test
    void copiesScopesAndAdditionalParameters() {
        Set<String> scopes = new HashSet<>(Set.of("message.read"));
        Map<String, Object> additionalParameters = new HashMap<>(Map.of("resource", "messages"));
        RefreshTokenRequest authentication = new RefreshTokenRequest(
                "refresh-token", CLIENT_PRINCIPAL, scopes, additionalParameters);

        scopes.add("message.write");
        additionalParameters.put("resource", "changed");

        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(Map.of("resource", "messages"), authentication.getAdditionalParameters());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getScopes().add("message.write"));
    }

    @Test
    void acceptsMissingScopesAndAdditionalParameters() {
        RefreshTokenRequest authentication = new RefreshTokenRequest("refresh-token", CLIENT_PRINCIPAL, null, null);

        assertEquals(Set.of(), authentication.getScopes());
        assertEquals(Map.of(), authentication.getAdditionalParameters());
    }

    @Test
    void rejectsMissingRefreshTokenOrClientPrincipal() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RefreshTokenRequest(" ", CLIENT_PRINCIPAL, Set.of(), Map.of()));
        assertThrows(
                NullPointerException.class,
                () -> new RefreshTokenRequest("refresh-token", null, Set.of(), Map.of()));
    }
}
