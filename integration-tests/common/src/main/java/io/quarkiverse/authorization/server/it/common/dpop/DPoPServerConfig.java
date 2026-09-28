package io.quarkiverse.authorization.server.it.common.dpop;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;

@UnlessBuildProfile("multiple-issuers")
@Singleton
public class DPoPServerConfig {

    public static final String RESOURCE_OWNER = "resource-owner";
    public static final String RESOURCE_OWNER_PASSWORD = "resource-owner-password";
    public static final String REDIRECT_URI = "https://client.example/callback";

    public void initializeDatabase(
            @Observes @Priority(200) StartupEvent event,
            DataSource dataSource,
            RegisteredClientRepository registeredClientRepository) {
        initializeSchema(dataSource);
        for (RegisteredClient client : clients()) {
            // Restart tests retain registrations as well as authorization and consent rows.
            if (registeredClientRepository.findById(client.getId()) == null)
                registeredClientRepository.save(client);
        }
    }

    private static java.util.List<RegisteredClient> clients() {
        var result = new java.util.ArrayList<RegisteredClient>();
        result.add(
                RegisteredClient.withId("dpop-fixture-registration")
                        .clientId("dpop-resource-server")
                        .clientSecret(BcryptUtil.bcryptHash("resource-secret"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                        .scope("message.read")
                        .scope("openid")
                        .build());
        for (String id : java.util.List.of(
                "public-jwt", "public-opaque", "public-no-refresh", "confidential")) {
            boolean confidential = id.equals("confidential");
            var client = RegisteredClient.withId(id)
                    .clientId(id)
                    .clientAuthenticationMethod(
                            confidential
                                    ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                                    : ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .scope("message.read")
                    .clientSettings(
                            ClientSettings.builder()
                                    .requireProofKey(true)
                                    .requireAuthorizationConsent(id.equals("public-opaque"))
                                    .build())
                    .tokenSettings(
                            io.quarkiverse.authorization.server.settings.TokenSettings.builder()
                                    .reuseRefreshTokens(id.equals("public-opaque"))
                                    .accessTokenFormat(
                                            id.equals("public-opaque")
                                                    ? io.quarkiverse.authorization.server.settings.OAuth2TokenFormat.REFERENCE
                                                    : io.quarkiverse.authorization.server.settings.OAuth2TokenFormat.SELF_CONTAINED)
                                    .build());
            if (!id.equals("public-no-refresh"))
                client.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            if (confidential)
                client.clientSecret(BcryptUtil.bcryptHash("confidential-secret"));
            result.add(client.build());
        }
        for (String id : java.util.List.of(
                "machine-jwt",
                "machine-opaque",
                "device-jwt",
                "device-opaque",
                "device-confidential",
                "device-no-refresh")) {
            boolean machine = id.startsWith("machine-");
            boolean confidential = machine || id.equals("device-confidential");
            var client = RegisteredClient.withId(id)
                    .clientId(id)
                    .clientAuthenticationMethod(
                            confidential
                                    ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                                    : ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(
                            machine
                                    ? AuthorizationGrantType.CLIENT_CREDENTIALS
                                    : AuthorizationGrantType.DEVICE_CODE)
                    .scope("message.read")
                    .tokenSettings(
                            io.quarkiverse.authorization.server.settings.TokenSettings.builder()
                                    .reuseRefreshTokens(id.equals("device-opaque"))
                                    .accessTokenFormat(
                                            id.endsWith("opaque")
                                                    ? io.quarkiverse.authorization.server.settings.OAuth2TokenFormat.REFERENCE
                                                    : io.quarkiverse.authorization.server.settings.OAuth2TokenFormat.SELF_CONTAINED)
                                    .build());
            if (confidential)
                client.clientSecret(BcryptUtil.bcryptHash("grant-secret"));
            if (machine)
                client.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
            else if (!id.equals("device-no-refresh"))
                client.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            result.add(client.build());
        }
        return result;
    }

    private static void initializeSchema(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                runSchemaIfMissing(
                        connection,
                        "oauth2_registered_client",
                        JdbcRegisteredClientRepository.SCHEMA_LOCATION);
                runSchemaIfMissing(
                        connection,
                        "oauth2_authorization",
                        JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
                runSchemaIfMissing(
                        connection,
                        "oauth2_authorization_consent",
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
            throw new IllegalStateException(
                    "Unable to initialize the authorization code test database", exception);
        }
    }

    private static void runSchemaIfMissing(
            Connection connection, String tableName, String schemaLocation)
            throws SQLException, IOException {
        try (ResultSet tables = connection
                .getMetaData()
                .getTables(
                        null,
                        null,
                        tableName.toUpperCase(java.util.Locale.ROOT),
                        new String[] { "TABLE" })) {
            if (tables.next()) {
                return;
            }
        }
        try (InputStream input = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(schemaLocation)) {
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
