package io.quarkiverse.authorization.server.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class OidcIdTokenTest {

    @Test
    void exposesTypedClaimsAndSurvivesJavaSerialization() throws Exception {
        Instant issuedAt = Instant.now();
        OidcIdToken token = OidcIdToken.withTokenValue("id-token")
                .issuer("https://issuer.example").subject("alice").audience(List.of("client"))
                .issuedAt(issuedAt).expiresAt(issuedAt.plusSeconds(1800)).authTime(issuedAt.minusSeconds(60))
                .nonce("nonce").authorizedParty("client").authenticationContextClass("acr")
                .authenticationMethods(List.of("pwd")).accessTokenHash("at-hash").authorizationCodeHash("c-hash")
                .build();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject(token);
        }
        OidcIdToken restored;
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            restored = (OidcIdToken) input.readObject();
        }
        assertEquals(token.getClaims(), restored.getClaims());
        assertEquals("alice", restored.getSubject());
        assertEquals(List.of("client"), restored.getAudience());
        assertEquals("https://issuer.example", restored.getIssuer().toString());
        assertEquals("nonce", restored.getNonce());
        assertEquals(issuedAt.minusSeconds(60), restored.getAuthenticatedAt());
        assertEquals(List.of("pwd"), restored.getAuthenticationMethods());
        assertThrows(UnsupportedOperationException.class, () -> restored.getClaims().clear());
    }

    @Test
    void rejectsEmptyClaimsAndNonInstantBuilderTimestamps() {
        assertThrows(IllegalArgumentException.class, () -> new OidcIdToken("token", null, null, Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> OidcIdToken.withTokenValue("token").claim(IdTokenClaimNames.IAT, 1L).build());
    }
}
