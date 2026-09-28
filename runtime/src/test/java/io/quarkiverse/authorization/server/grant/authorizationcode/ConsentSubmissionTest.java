package io.quarkiverse.authorization.server.grant.authorizationcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class ConsentSubmissionTest {

    @Test
    void representsAuthorizationConsent() {
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .build();
        Set<String> scopes = new LinkedHashSet<>(Set.of("message.read"));
        Map<String, Object> additionalParameters = new LinkedHashMap<>(Map.of("action", "approve"));

        ConsentSubmission authentication = new ConsentSubmission(
                "https://issuer.example.com/oauth2/authorize",
                "messaging-client",
                principal,
                "state",
                scopes,
                additionalParameters);

        scopes.add("message.write");
        additionalParameters.put("tenant", "internal");
        assertSame(principal, authentication.getPrincipal());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(Map.of("action", "approve"), authentication.getAdditionalParameters());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getAdditionalParameters().put("tenant", "internal"));
    }
}
