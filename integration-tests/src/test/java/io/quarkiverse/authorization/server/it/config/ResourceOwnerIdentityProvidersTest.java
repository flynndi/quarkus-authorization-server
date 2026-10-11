package io.quarkiverse.authorization.server.it.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.h2.jdbcx.JdbcConnectionPool;
import org.h2.tools.RunScript;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.repository.UserRepository;
import io.quarkus.security.StringPermission;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.smallrye.mutiny.Uni;

class ResourceOwnerIdentityProvidersTest {

    private static final AuthenticationRequestContext CONTEXT = action -> Uni.createFrom().item(action);

    private JdbcConnectionPool dataSource;
    private ResourceOwnerIdentityProviders providers;

    @BeforeEach
    void setUp() throws Exception {
        this.dataSource = JdbcConnectionPool.create("jdbc:h2:mem:" + UUID.randomUUID() + ";NON_KEYWORDS=USER,ROLE", "sa", "");
        try (Connection connection = this.dataSource.getConnection();
                Reader schema = new InputStreamReader(
                        Objects.requireNonNull(ResourceOwnerIdentityProvidersTest.class.getResourceAsStream("/sql-schema.sql")),
                        StandardCharsets.UTF_8);
                Statement statement = connection.createStatement()) {
            RunScript.execute(connection, schema);
            statement.executeUpdate("UPDATE permission SET code = 'user:read' WHERE code = 'admin'");
        }
        this.providers = new ResourceOwnerIdentityProviders(new UserRepository(this.dataSource));
    }

    @AfterEach
    void closeDataSource() {
        this.dataSource.dispose();
    }

    @Test
    void passwordAuthenticationGrantsUserPermissionsSeparatelyFromRoles() {
        var request = new UsernamePasswordAuthenticationRequest("admin", new PasswordCredential("password".toCharArray()));

        var identity = this.providers.resourceOwnerIdentityProvider().authenticate(request, CONTEXT).await().indefinitely();

        ResourceOwnerIdentityProvidersTest.assertUserPermissions(identity);
    }

    @Test
    void trustedAuthenticationReloadsCurrentUserPermissions() throws Exception {
        var provider = this.providers.trustedResourceOwnerIdentityProvider();
        var request = new TrustedAuthenticationRequest("admin");

        var identity = provider.authenticate(request, CONTEXT).await().indefinitely();

        ResourceOwnerIdentityProvidersTest.assertUserPermissions(identity);

        try (Connection connection = this.dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("DELETE FROM role_permission");
        }

        var restored = provider.authenticate(request, CONTEXT).await().indefinitely();

        assertEquals(Set.of("admin"), restored.getRoles());
        assertFalse(restored.checkPermission(new StringPermission("user", "read")).await().indefinitely());
    }

    private static void assertUserPermissions(SecurityIdentity identity) {
        assertEquals("admin", identity.getPrincipal().getName());
        assertEquals(Set.of("admin"), identity.getRoles());
        assertTrue(identity.checkPermission(new StringPermission("user", "read")).await().indefinitely());
        assertFalse(identity.checkPermission(new StringPermission("user", "write")).await().indefinitely());
        assertFalse(identity.checkPermission(new StringPermission("admin")).await().indefinitely());
    }
}
