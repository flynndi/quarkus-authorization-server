package io.quarkiverse.authorization.server.it.deviceauthorization;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/** JDBC-backed fixture used only by the Device Authorization integration application. */
@Singleton
public class DeviceAuthorizationServerConfig {

    static final String PUBLIC_CLIENT = "public-device";
    static final String CONFIDENTIAL_CLIENT = "confidential-device";
    static final String CONFIDENTIAL_SECRET = "confidential-device-secret";
    static final String SHORT_LIVED_CLIENT = "short-device";
    static final String SHORT_LIVED_SECRET = "short-device-secret";
    static final String RESOURCE_OWNER = "resource-owner";
    static final String RESOURCE_OWNER_PASSWORD = "resource-owner-password";

    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource, JdbcJsonCodec jsonCodec) {
        return new JdbcRegisteredClientRepository(dataSource, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients,
            JdbcJsonCodec jsonCodec) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationConsentService consents(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(dataSource, clients);
    }

    void initialize(@Observes @Priority(100) StartupEvent event, DataSource dataSource,
            RegisteredClientRepository clients) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            schema(connection, "OAUTH2_REGISTERED_CLIENT", JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            schema(connection, "OAUTH2_AUTHORIZATION", JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
            schema(connection, "OAUTH2_AUTHORIZATION_CONSENT", JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);
        }

        saveIfMissing(clients, resourceServer());
        saveIfMissing(clients, publicDevice());
        saveIfMissing(clients, confidentialDevice());
        saveIfMissing(clients, shortLivedDevice());
    }

    @Produces
    @Singleton
    IdentityProvider<UsernamePasswordAuthenticationRequest> resourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
                return UsernamePasswordAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                if (!RESOURCE_OWNER.equals(request.getUsername())
                        || !Arrays.equals(RESOURCE_OWNER_PASSWORD.toCharArray(), request.getPassword().getPassword())) {
                    return Uni.createFrom().failure(new AuthenticationFailedException());
                }
                return Uni.createFrom().item(resourceOwnerIdentity(request.getUsername()));
            }
        };
    }

    @Produces
    @Singleton
    IdentityProvider<TrustedAuthenticationRequest> trustedResourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<TrustedAuthenticationRequest> getRequestType() {
                return TrustedAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                return RESOURCE_OWNER.equals(request.getPrincipal())
                        ? Uni.createFrom().item(resourceOwnerIdentity(request.getPrincipal()))
                        : Uni.createFrom().nullItem();
            }
        };
    }

    private static SecurityIdentity resourceOwnerIdentity(String principalName) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(principalName))
                .addRole("user")
                .build();
    }

    private static RegisteredClient resourceServer() {
        return confidential("resource-server-registration", "resource-server", "resource-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private static RegisteredClient publicDevice() {
        return RegisteredClient.withId("public-device-registration")
                .clientId(PUBLIC_CLIENT)
                .clientName("Public Device Client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .build();
    }

    private static RegisteredClient confidentialDevice() {
        return confidential("confidential-device-registration", CONFIDENTIAL_CLIENT, CONFIDENTIAL_SECRET)
                .clientName("Confidential Device Client")
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .build())
                .build();
    }

    private static RegisteredClient shortLivedDevice() {
        return confidential("short-device-registration", SHORT_LIVED_CLIENT, SHORT_LIVED_SECRET)
                .clientName("Short-lived Device Client")
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .scope("message.read")
                .tokenSettings(TokenSettings.builder()
                        .deviceCodeTimeToLive(Duration.ofSeconds(3))
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .build())
                .build();
    }

    private static RegisteredClient.Builder confidential(String id, String clientId, String secret) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(BcryptUtil.bcryptHash(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    private static void saveIfMissing(RegisteredClientRepository clients, RegisteredClient candidate) {
        if (clients.findById(candidate.getId()) == null) {
            clients.save(candidate);
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
