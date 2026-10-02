package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class PushedAuthorizationRequestsTest {
    private final InMemoryOAuth2AuthorizationService authorizations = new InMemoryOAuth2AuthorizationService();
    private final PushedAuthorizationRequests pushed = new PushedAuthorizationRequests(this.authorizations);
    private final RegisteredClient client = RegisteredClient.withId("id").clientId("client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://client.example/callback")
            .build();

    @Test
    void jdbcReplayPreservesTheRequestAndEnforcesItsExpiry() {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:" + java.util.UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");
        JdbcTestSupport.executeSchema(dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(dataSource, JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        var clients = new JdbcRegisteredClientRepository(dataSource);
        clients.save(this.client);
        var writer = new PushedAuthorizationRequests(new JdbcOAuth2AuthorizationService(dataSource, clients));
        var response = writer.save(PushedAuthorizationRequestsTest.request("client", Map.of("nonce", "n")), this.client);
        var repository = new JdbcOAuth2AuthorizationService(dataSource, new JdbcRegisteredClientRepository(dataSource));
        var reader = new PushedAuthorizationRequests(repository);
        var reference = PushedAuthorizationRequestsTest.reference("client", response.requestUri());
        var restored = reader.resolve(reference);
        assertEquals("n", restored.request().getAdditionalParameters().get("nonce"));
        repository.save(OAuth2Authorization.from(restored.authorization())
                .attribute(OAuth2AuthorizationRequest.PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME, Instant.EPOCH).build());
        assertThrows(AuthorizationRequestException.class, () -> reader.resolve(reference));
        assertNull(repository.findById(restored.authorization().getId()));
    }

    @Test
    void referenceRestoresParametersButKeepsTheCurrentBrowserIdentityAndEndpoint() {
        var result = this.pushed
                .save(PushedAuthorizationRequestsTest.request("client", Map.of("nonce", "n", "client_secret", "secret",
                        "client_assertion", "assertion", "client_assertion_type", "jwt")), this.client);
        assertEquals(300, result.expiresIn());
        var restored = this.pushed.resolve(PushedAuthorizationRequestsTest.reference("client", result.requestUri()));
        assertEquals("browser-user", restored.request().getPrincipal().getPrincipal().getName());
        assertEquals("https://server.example/authorize", restored.request().getAuthorizationUri());
        assertEquals("state", restored.request().getState());
        assertEquals(Set.of("openid"), restored.request().getScopes());
        assertEquals(Map.of("nonce", "n"), restored.request().getAdditionalParameters());
        assertNull(this.authorizations.findByToken(result.requestUri(), new OAuth2TokenType("state")));
        assertNull(restored.authorization().getAttribute("state"));
        assertNotNull(this.authorizations.findById(restored.authorization().getId()));
        this.pushed.consume(restored);
        assertThrows(AuthorizationRequestException.class,
                () -> this.pushed.resolve(PushedAuthorizationRequestsTest.reference("client", result.requestUri())));
    }

    @Test
    void forgedExpiredAndCrossClientReferencesCannotSelectACallbackOrDeleteAnotherClientsRequest() {
        var result = this.pushed.save(PushedAuthorizationRequestsTest.request("client", Map.of()), this.client);
        var reference = PushedAuthorizationRequestsTest.reference("client", result.requestUri());
        var resolved = this.pushed.resolve(reference);
        var crossClient = assertThrows(AuthorizationRequestException.class,
                () -> this.pushed.resolve(PushedAuthorizationRequestsTest.reference("other", result.requestUri())));
        assertNull(crossClient.getRedirect());
        assertNotNull(this.authorizations.findById(resolved.authorization().getId()));
        this.authorizations.save(OAuth2Authorization.from(resolved.authorization())
                .attribute(OAuth2AuthorizationRequest.PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME, Instant.EPOCH).build());
        assertNull(assertThrows(AuthorizationRequestException.class, () -> this.pushed.resolve(reference)).getRedirect());
        assertNull(this.authorizations.findById(resolved.authorization().getId()));
        for (String uri : new String[] { "https://attacker.example/request", "urn:ietf:params:oauth:request_uri:",
                PushedAuthorizationRequests.URI_PREFIX + "a".repeat(43), result.requestUri() + "___9999999999999" }) {
            assertNull(assertThrows(AuthorizationRequestException.class,
                    () -> this.pushed.resolve(PushedAuthorizationRequestsTest.reference("client", uri))).getRedirect());
        }
    }

    @Test
    void anOrdinaryAuthorizationCannotBeUsedAsAParRecord() {
        String id = "a".repeat(43);
        this.authorizations.save(OAuth2Authorization.withRegisteredClient(this.client).id(id).principalName("user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2AuthorizationRequest.class.getName(), OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("https://server.example/authorize").clientId("client").build())
                .build());
        assertNull(assertThrows(AuthorizationRequestException.class, () -> this.pushed.resolve(
                PushedAuthorizationRequestsTest.reference("client", PushedAuthorizationRequests.URI_PREFIX + id)))
                .getRedirect());
        assertNotNull(this.authorizations.findById(id));
    }

    private static AuthorizationRequest request(String client, Map<String, Object> parameters) {
        return new AuthorizationRequest("https://server.example/par", client,
                QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(client)).build(),
                "https://client.example/callback", "state", Set.of("openid"), parameters);
    }

    private static AuthorizationRequest reference(String client, String uri) {
        return new AuthorizationRequest("https://server.example/authorize", client,
                QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal("browser-user")).build(),
                "https://attacker.example/callback", "untrusted-state", Set.of("other"), Map.of("request_uri", uri));
    }
}
