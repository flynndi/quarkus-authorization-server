package io.quarkiverse.authorization.server.grant.clientcredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class ClientCredentialsRequestTest {

    private final SecurityIdentity clientPrincipal = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("machine-client"))
            .build();

    @Test
    void retainsClientAndDefensivelyCopiesRequestValues() {
        Set<String> scopes = new HashSet<>(Set.of("message.read"));
        Map<String, Object> additionalParameters = new HashMap<>(Map.of("custom", "value"));
        ClientCredentialsRequest authentication = new ClientCredentialsRequest(this.clientPrincipal, scopes,
                additionalParameters);
        scopes.clear();
        additionalParameters.clear();

        assertSame(this.clientPrincipal, authentication.getClientPrincipal());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, authentication.getGrantType());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(Map.of("custom", "value"), authentication.getAdditionalParameters());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getScopes().add("message.write"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getAdditionalParameters().put("another", "value"));
    }

    @Test
    void treatsNullOptionalValuesAsEmpty() {
        ClientCredentialsRequest authentication = new ClientCredentialsRequest(this.clientPrincipal, null, null);

        assertTrue(authentication.getScopes().isEmpty());
        assertTrue(authentication.getAdditionalParameters().isEmpty());
    }

    @Test
    void rejectsNullClient() {
        assertThrows(
                NullPointerException.class,
                () -> new ClientCredentialsRequest(null, Set.of(), Map.of()));
    }
}
