package io.quarkiverse.authorization.server.it.multipleissuers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import javax.sql.DataSource;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.tenant.AuthorizationServerTenant;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkus.arc.profile.IfBuildProfile;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.smallrye.common.annotation.Identifier;
import io.smallrye.jwt.util.KeyUtils;

/** Two application-owned JDBC component groups, selected by the extension through CDI. */
@Singleton
@IfBuildProfile("multiple-issuers")
public class TenantConfiguration {
    @Produces
    @Singleton
    @Identifier("alpha")
    AuthorizationServerTenant alpha(@io.quarkus.agroal.DataSource("alpha") DataSource dataSource, JdbcJsonCodec jsonCodec)
            throws Exception {
        return TenantConfiguration.create("alpha", dataSource, jsonCodec);
    }

    @Produces
    @Singleton
    @Identifier("beta")
    AuthorizationServerTenant beta(@io.quarkus.agroal.DataSource("beta") DataSource dataSource, JdbcJsonCodec jsonCodec)
            throws Exception {
        return TenantConfiguration.create("beta", dataSource, jsonCodec);
    }

    private static AuthorizationServerTenant create(String tenant, DataSource dataSource, JdbcJsonCodec jsonCodec)
            throws Exception {
        TenantConfiguration.initializeSchema(dataSource);
        var clients = new JdbcRegisteredClientRepository(dataSource, jsonCodec);
        if (clients.findByClientId("shared") == null) {
            clients.save(RegisteredClient.withId("same-id").clientId("shared").clientName(tenant + " demo")
                    .clientSecret(BcryptUtil.bcryptHash(tenant + "-secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).scope("openid").scope(tenant)
                    .redirectUri("https://client.example/callback").postLogoutRedirectUri("https://client.example/logout")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build());
        }
        // Demo keys are checked-in test material. A real application supplies its own key source.
        var key = new AuthorizationServerKeySource.Key(tenant, SignatureAlgorithm.RS256,
                KeyUtils.readPrivateKey(tenant + "-private.pem"), KeyUtils.readPublicKey(tenant + "-public.pem"));
        return new AuthorizationServerTenant(clients, new JdbcOAuth2AuthorizationService(dataSource, clients, jsonCodec),
                new JdbcOAuth2AuthorizationConsentService(dataSource, clients),
                () -> new AuthorizationServerKeySource.KeySet(List.of(key), tenant));
    }

    private static void initializeSchema(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                TenantConfiguration.runSchemaIfMissing(connection, "oauth2_registered_client",
                        JdbcRegisteredClientRepository.SCHEMA_LOCATION);
                TenantConfiguration.runSchemaIfMissing(connection, "oauth2_authorization",
                        JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
                TenantConfiguration.runSchemaIfMissing(connection, "oauth2_authorization_consent",
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
