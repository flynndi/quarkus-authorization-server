package io.quarkiverse.authorization.server.example.clientcredentials;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;

import javax.sql.DataSource;

import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;

/** Registers one machine client in the example's embedded H2 database. */
@Singleton
public class ClientCredentialsServerConfig {

    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(dataSource);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients);
    }

    void initialize(@Observes StartupEvent event, DataSource dataSource,
            RegisteredClientRepository clients) throws SQLException {
        // The example initializes H2 with the extension's schema; applications own their migrations.
        try (Connection connection = dataSource.getConnection()) {
            ClientCredentialsServerConfig.schema(connection, "OAUTH2_REGISTERED_CLIENT",
                    JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            ClientCredentialsServerConfig.schema(connection, "OAUTH2_AUTHORIZATION",
                    JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        }
        if (clients.findById("machine-registration") == null) {
            clients.save(RegisteredClient.withId("machine-registration").clientId("machine-client")
                    .clientSecret(BcryptUtil.bcryptHash("machine-secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("message.read")
                    .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(2)).build())
                    .build());
        }
    }

    private static void schema(Connection connection, String table, String resource) throws SQLException {
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
