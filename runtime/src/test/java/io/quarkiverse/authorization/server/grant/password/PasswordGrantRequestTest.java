package io.quarkiverse.authorization.server.grant.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

class PasswordGrantRequestTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("messaging-client"))
            .build();

    @Test
    void exposesPasswordGrantRequestWithoutUsingGrantCredentials() {
        PasswordGrantRequest authentication = new PasswordGrantRequest(
                CLIENT_PRINCIPAL,
                "resource-owner",
                "resource-owner-password",
                Map.of("tenant", "internal"),
                Set.of("message.read"));

        assertEquals(AuthorizationGrantType.PASSWORD, authentication.getGrantType());
        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("resource-owner", authentication.getUsername());
        assertEquals("resource-owner-password", authentication.getPassword());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(Map.of("tenant", "internal"), authentication.getAdditionalParameters());
    }

    @Test
    void copiesScopesAndAdditionalParameters() {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("tenant", "internal");
        Set<String> scopes = new HashSet<>();
        scopes.add("message.read");

        PasswordGrantRequest authentication = new PasswordGrantRequest(
                CLIENT_PRINCIPAL,
                "resource-owner",
                "resource-owner-password",
                additionalParameters,
                scopes);
        additionalParameters.put("tenant", "changed");
        scopes.add("message.write");

        assertEquals(Map.of("tenant", "internal"), authentication.getAdditionalParameters());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getAdditionalParameters().put("resource", "messages"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getScopes().add("message.write"));
    }

    @Test
    void toStringDoesNotExposeCredentialsOrParameters() {
        PasswordGrantRequest authentication = new PasswordGrantRequest(
                CLIENT_PRINCIPAL,
                "resource-owner",
                "resource-owner-password",
                Map.of("tenant", "private-extension-value"),
                Set.of("message.read"));

        String value = authentication.toString();

        assertFalse(value.contains("resource-owner"));
        assertFalse(value.contains("resource-owner-password"));
        assertFalse(value.contains("private-extension-value"));
    }

    @Test
    void requiresClientAndResourceOwnerCredentials() {
        assertThrows(
                NullPointerException.class,
                () -> new PasswordGrantRequest(
                        null,
                        "resource-owner",
                        "resource-owner-password",
                        Map.of(),
                        Set.of()));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PasswordGrantRequest(
                        CLIENT_PRINCIPAL,
                        " ",
                        "resource-owner-password",
                        Map.of(),
                        Set.of()));
        assertThrows(
                IllegalArgumentException.class,
                () -> new PasswordGrantRequest(
                        CLIENT_PRINCIPAL, "resource-owner", " ", Map.of(), Set.of()));
    }
}
