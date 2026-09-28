package io.quarkiverse.authorization.server.example.config;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.UUID;

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
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

@Singleton
public class AuthorizationServerConfig {

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

    public void initializeDatabase(@Observes StartupEvent event,
            DataSource dataSource,
            RegisteredClientRepository registeredClientRepository) {
        AuthorizationServerConfig.initializeSchema(dataSource);
        if (registeredClientRepository.findByClientId("quarkus-authorization-server") != null) {
            return;
        }
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("quarkus-authorization-server")
                .clientName("Quarkus Authorization Server")
                .clientSecret(BcryptUtil.bcryptHash("secret"))
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .scope("openid")
                .scope("profile")
                .build();
        registeredClientRepository.save(registeredClient);
    }

    private static void initializeSchema(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            AuthorizationServerConfig.runSchemaIfMissing(connection, "OAUTH2_REGISTERED_CLIENT",
                    JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            AuthorizationServerConfig.runSchemaIfMissing(connection, "OAUTH2_AUTHORIZATION",
                    JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to initialize the embedded authorization server database", exception);
        }
    }

    private static void runSchemaIfMissing(Connection connection, String tableName, String schemaLocation)
            throws SQLException {
        try (ResultSet tables = connection.getMetaData().getTables(null, null, tableName, new String[] { "TABLE" })) {
            if (tables.next()) {
                return;
            }
        }
        try (Statement statement = connection.createStatement()) {
            statement.execute("RUNSCRIPT FROM 'classpath:" + schemaLocation + "'");
        }
    }

    @Produces
    @Singleton
    public IdentityProvider<UsernamePasswordAuthenticationRequest> resourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
                return UsernamePasswordAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                if (!"resource-owner".equals(request.getUsername())
                        || !Arrays.equals("resource-owner-password".toCharArray(), request.getPassword().getPassword())) {
                    return Uni.createFrom().failure(new AuthenticationFailedException());
                }
                return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                        .addRole("user")
                        .build());
            }
        };
    }
}
