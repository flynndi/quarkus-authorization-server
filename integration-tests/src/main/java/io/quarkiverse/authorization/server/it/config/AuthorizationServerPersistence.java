package io.quarkiverse.authorization.server.it.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

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
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;

/** JDBC storage and schema setup for the shared confidential client and demo users. */
@Singleton
public class AuthorizationServerPersistence {

    public static final String CLIENT_REGISTRATION_ID = UUID.randomUUID().toString();
    public static final String CLIENT_ID = "quarkus-authorization-server";
    public static final String CLIENT_PASSWORD = "quarkus-authorization-server-password";
    public static final String REDIRECT_URI = "https://quarkus-authorization-server.dev/playground/callback";
    public static final String ADDITIONAL_REDIRECT_URI = "https://authorization-server.dev/playground/callback";
    public static final String POSTMAN_REDIRECT_URI = "https://oauth.pstmn.io/v1/callback";

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

    public void initializeSqlSchema(@Observes StartupEvent event, DataSource dataSource) {
        try (InputStream input = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream("sql-schema.sql")) {
            if (input == null) {
                throw new IllegalStateException("Schema resource not found: sql-schema.sql");
            }
            String script = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            try (Connection connection = dataSource.getConnection()) {
                for (String sql : script.split(";")) {
                    if (sql.isBlank()) {
                        continue;
                    }
                    try (Statement statement = connection.createStatement()) {
                        statement.execute(sql);
                    }
                }
            }
        } catch (SQLException | IOException exception) {
            throw new IllegalStateException("Unable to initialize the RBAC schema", exception);
        }
    }

    public void initializeDatabase(@Observes StartupEvent event, DataSource dataSource, RegisteredClientRepository clients) {
        AuthorizationServerPersistence.initializeSchema(dataSource);
        clients.save(RegisteredClient.withId(CLIENT_REGISTRATION_ID)
                .clientId(CLIENT_ID)
                .clientName(CLIENT_ID)
                .clientSecret(BcryptUtil.bcryptHash(CLIENT_PASSWORD))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .redirectUri(REDIRECT_URI)
                .redirectUri(ADDITIONAL_REDIRECT_URI)
                .redirectUri(POSTMAN_REDIRECT_URI)
                .scope("openid")
                .scope("profile")
                .scope("securityIdentity")
                .scope("jsonWebToken")
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
