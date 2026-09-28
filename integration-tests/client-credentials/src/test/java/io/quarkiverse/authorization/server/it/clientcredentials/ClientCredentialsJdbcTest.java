package io.quarkiverse.authorization.server.it.clientcredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import javax.sql.DataSource;

import jakarta.inject.Inject;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;

/** HTTP issuance through CDI-managed JDBC services, followed by domain and raw committed-row assertions. */
@QuarkusTest
class ClientCredentialsJdbcTest {

    @Inject
    DataSource dataSource;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    OAuth2AuthorizationService authorizations;

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void persistsHttpIssuedMachineAuthorizationWithoutResourceOwnerCredentials(boolean requestScope) throws SQLException {
        assertInstanceOf(JdbcRegisteredClientRepository.class, this.clients);
        assertInstanceOf(JdbcOAuth2AuthorizationService.class, this.authorizations);
        var client = this.clients.findByClientId("machine-client");
        assertTrue(client.getRedirectUris().isEmpty());
        assertNotEquals("machine-secret", client.getClientSecret());
        assertTrue(client.getClientSecret().startsWith("$2"));

        var request = ClientCredentialsTest.tokenRequest("machine-client", "machine-secret");
        if (requestScope) {
            request.formParam("scope", "message.read openid");
        }
        String token = request.post("/oauth2/token").then().statusCode(200).extract().path("access_token");
        var restored = this.authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        Set<String> scopes = requestScope ? Set.of("message.read", "openid") : Set.of();
        assertNotNull(restored);
        assertEquals(client.getId(), restored.getRegisteredClientId());
        assertEquals(client.getClientId(), restored.getPrincipalName());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, restored.getAuthorizationGrantType());
        assertEquals(scopes, restored.getAuthorizedScopes());
        assertEquals(scopes, restored.getAccessToken().getToken().getScopes());
        assertTrue(restored.getAttributes().isEmpty());
        assertNull(restored.getRefreshToken());
        assertNull(restored.getToken(OidcIdToken.class));
        assertTrue(restored.getAccessToken().isActive());
        assertFalse(restored.getAccessToken().isInvalidated());

        // Decoding here compares persistence with the wire claims; resource-server tests separately prove verification.
        var claims = new JsonPath(new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8));
        assertEquals(claims.getString("iss"), restored.getAccessToken().getClaims().get("iss"));
        assertEquals("machine-client", restored.getAccessToken().getClaims().get("sub"));
        assertEquals(List.of("machine-client"), restored.getAccessToken().getClaims().get("aud"));
        assertEquals(claims.getString("jti"), restored.getAccessToken().getClaims().get("jti"));
        if (requestScope) {
            assertEquals(scopes, restored.getAccessToken().getClaims().get("scope"));
        } else {
            assertFalse(restored.getAccessToken().getClaims().containsKey("scope"));
        }
        assertEquals(Instant.ofEpochSecond(claims.getLong("iat")),
                restored.getAccessToken().getToken().getIssuedAt().truncatedTo(ChronoUnit.SECONDS));
        assertEquals(Instant.ofEpochSecond(claims.getLong("exp")),
                restored.getAccessToken().getToken().getExpiresAt().truncatedTo(ChronoUnit.SECONDS));
        assertEquals(Duration.ofMinutes(2), Duration.between(restored.getAccessToken().getToken().getIssuedAt(),
                restored.getAccessToken().getToken().getExpiresAt()));

        try (var connection = this.dataSource.getConnection();
                var statement = connection.prepareStatement("""
                        SELECT registered_client_id, principal_name, authorization_grant_type,
                               authorized_scopes, access_token_scopes, access_token_value,
                               access_token_issued_at, access_token_expires_at,
                               authorization_code_value, refresh_token_value, oidc_id_token_value
                        FROM oauth2_authorization WHERE id = ?
                        """)) {
            statement.setString(1, restored.getId());
            try (var rows = statement.executeQuery()) {
                assertTrue(rows.next());
                assertEquals(client.getId(), rows.getString("registered_client_id"));
                assertEquals("machine-client", rows.getString("principal_name"));
                assertEquals("client_credentials", rows.getString("authorization_grant_type"));
                for (String column : List.of("authorized_scopes", "access_token_scopes")) {
                    if (requestScope) {
                        assertEquals(scopes, Set.of(rows.getString(column).split(",")));
                    } else {
                        assertNull(rows.getString(column));
                    }
                }
                assertEquals(token, new String(rows.getBytes("access_token_value"), StandardCharsets.UTF_8));
                assertEquals(restored.getAccessToken().getToken().getIssuedAt(),
                        rows.getTimestamp("access_token_issued_at").toInstant());
                assertEquals(restored.getAccessToken().getToken().getExpiresAt(),
                        rows.getTimestamp("access_token_expires_at").toInstant());
                assertNull(rows.getBytes("authorization_code_value"));
                assertNull(rows.getBytes("refresh_token_value"));
                assertNull(rows.getBytes("oidc_id_token_value"));
                assertFalse(rows.next());
            }
        }
    }
}
