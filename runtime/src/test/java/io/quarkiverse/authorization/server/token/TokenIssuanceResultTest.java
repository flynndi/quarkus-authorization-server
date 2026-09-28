package io.quarkiverse.authorization.server.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class TokenIssuanceResultTest {
    @Test
    void resultCannotChangeWhenCallerMutatesAdditionalResponseParameters() {
        RegisteredClient client = RegisteredClient.withId("client")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        var identity = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("client"))
                .build();
        Instant issuedAt = Instant.now();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access",
                issuedAt,
                issuedAt.plusSeconds(60),
                Set.of("read"));
        Map<String, Object> parameters = new HashMap<>(Map.of("id_token", "original"));
        TokenIssuanceResult result = new TokenIssuanceResult(client, identity, accessToken, null, parameters);

        parameters.put("id_token", "changed");

        assertEquals("original", result.getAdditionalParameters().get("id_token"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> result.getAdditionalParameters().clear());
    }
}
