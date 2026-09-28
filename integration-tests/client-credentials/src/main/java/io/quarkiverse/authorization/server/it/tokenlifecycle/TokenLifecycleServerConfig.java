package io.quarkiverse.authorization.server.it.tokenlifecycle;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;

/** Disposable JDBC fixture for cross-grant token lifecycle verification. */
@Singleton
public class TokenLifecycleServerConfig {

    static final String REDIRECT_URI = "https://client.example/callback";
    static final String RESOURCE_OWNER = "resource-owner";
    static final String RESOURCE_OWNER_PASSWORD = "resource-owner-password";
    static final String INITIAL_ACCESS_TOKEN = "token-lifecycle-initial-access-token";

    void initialize(
            @Observes @Priority(250) StartupEvent event,
            DataSource dataSource,
            RegisteredClientRepository clients,
            OAuth2AuthorizationService authorizations)
            throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            schema(
                    connection,
                    "OAUTH2_REGISTERED_CLIENT",
                    JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            schema(
                    connection,
                    "OAUTH2_AUTHORIZATION",
                    JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
            schema(
                    connection,
                    "OAUTH2_AUTHORIZATION_CONSENT",
                    JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);
        }

        saveIfMissing(clients, resourceServer());
        saveIfMissing(clients, opaqueMachineClient());
        saveIfMissing(clients, shortLivedOpaqueClient());
        saveIfMissing(clients, jwtMachineClient());

    }

    private static RegisteredClient resourceServer() {
        return confidential("resource-server-registration", "resource-server", "resource-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private static RegisteredClient opaqueMachineClient() {
        return confidential("opaque-machine-registration", "opaque-machine", "opaque-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .tokenSettings(referenceTokens(Duration.ofMinutes(5)))
                .build();
    }

    private static RegisteredClient shortLivedOpaqueClient() {
        return confidential("short-opaque-registration", "short-opaque", "short-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .tokenSettings(referenceTokens(Duration.ofSeconds(3)))
                .build();
    }

    private static RegisteredClient jwtMachineClient() {
        return confidential("jwt-machine-registration", "jwt-machine", "jwt-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .build();
    }

    private static RegisteredClient.Builder confidential(
            String id, String clientId, String secret) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(BcryptUtil.bcryptHash(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    private static TokenSettings referenceTokens(Duration accessTokenTtl) {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(accessTokenTtl)
                .build();
    }

    private static RegisteredClient saveIfMissing(
            RegisteredClientRepository clients, RegisteredClient candidate) {
        RegisteredClient existing = clients.findById(candidate.getId());
        if (existing != null) {
            return existing;
        }
        clients.save(candidate);
        return candidate;
    }

    private static void schema(Connection connection, String table, String resource)
            throws SQLException {
        try (var tables = connection.getMetaData().getTables(null, null, table, new String[] { "TABLE" })) {
            if (tables.next()) {
                return;
            }
        }
        try (var statement = connection.createStatement()) {
            statement.execute("RUNSCRIPT FROM 'classpath:" + resource + "'");
        }
    }
}
