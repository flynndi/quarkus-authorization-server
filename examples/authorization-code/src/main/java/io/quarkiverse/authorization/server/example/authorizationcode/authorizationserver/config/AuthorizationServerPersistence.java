package io.quarkiverse.authorization.server.example.authorizationcode.authorizationserver.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkus.runtime.StartupEvent;

/** JDBC storage and schema setup for a single public PKCE client in the browser example. */
@Singleton
public class AuthorizationServerPersistence {

    public static final String PUBLIC_CLIENT_REGISTRATION_ID = "authorization-code-public-client-registration";
    public static final String PUBLIC_CLIENT_ID = "authorization-code-public-client";
    public static final String REDIRECT_URI = "http://localhost:5173/callback";

    @Produces
    @Singleton
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(dataSource);
    }

    @Produces
    @Singleton
    public OAuth2AuthorizationService authorizationService(DataSource dataSource,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(dataSource, registeredClientRepository);
    }

    @Produces
    @Singleton
    public OAuth2AuthorizationConsentService authorizationConsentService(DataSource dataSource,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(dataSource, registeredClientRepository);
    }

    public void initializeDatabase(@Observes StartupEvent event,
            DataSource dataSource, RegisteredClientRepository clients) {
        AuthorizationServerPersistence.initializeSchema(dataSource);
        clients.save(RegisteredClient.withId(PUBLIC_CLIENT_REGISTRATION_ID)
                .clientId(PUBLIC_CLIENT_ID)
                .clientName("Authorization Code Public Client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .postLogoutRedirectUri("http://localhost:5173/")
                .scope("openid")
                .scope("profile")
                .scope("message.read")
                .build());
    }

    private static void initializeSchema(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                AuthorizationServerPersistence.runSchemaIfMissing(connection, "oauth2_registered_client",
                        JdbcRegisteredClientRepository.SCHEMA_LOCATION);
                AuthorizationServerPersistence.runSchemaIfMissing(connection, "oauth2_authorization",
                        JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
                AuthorizationServerPersistence.runSchemaIfMissing(connection, "oauth2_authorization_consent",
                        JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);
                connection.commit();
            } catch (SQLException | IOException exception) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackException) {
                    exception.addSuppressed(rollbackException);
                }
                throw exception;
            }
        } catch (SQLException | IOException exception) {
            throw new IllegalStateException("Unable to initialize the authorization code test database", exception);
        }
    }

    private static void runSchemaIfMissing(Connection connection, String tableName, String schemaLocation)
            throws SQLException, IOException {
        try (ResultSet tables = connection.getMetaData().getTables(null, null,
                tableName.toUpperCase(java.util.Locale.ROOT), new String[] { "TABLE" })) {
            if (tables.next()) {
                return;
            }
        }
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream(schemaLocation)) {
            if (input == null) {
                throw new IllegalStateException("Schema resource not found: " + schemaLocation);
            }
            String script = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            for (String sql : script.split(";")) {
                if (!sql.isBlank()) {
                    try (Statement statement = connection.createStatement()) {
                        statement.execute(sql);
                    }
                }
            }
        }
    }
}
