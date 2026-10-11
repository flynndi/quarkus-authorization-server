package io.quarkiverse.authorization.server.it.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.h2.jdbcx.JdbcConnectionPool;
import org.h2.tools.RunScript;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.entity.Permission;

class UserRepositoryTest {

    private JdbcConnectionPool dataSource;
    private UserRepository repository;

    @BeforeEach
    void setUp() throws Exception {
        this.dataSource = JdbcConnectionPool.create("jdbc:h2:mem:" + UUID.randomUUID() + ";NON_KEYWORDS=USER,ROLE", "sa", "");
        this.dataSource.setMaxConnections(1);
        this.dataSource.setLoginTimeout(1);
        try (Connection connection = this.dataSource.getConnection();
                Reader schema = new InputStreamReader(
                        Objects.requireNonNull(UserRepositoryTest.class.getResourceAsStream("/sql-schema.sql")),
                        StandardCharsets.UTF_8)) {
            RunScript.execute(connection, schema);
        }
        this.repository = new UserRepository(this.dataSource);
    }

    @AfterEach
    void closeDataSource() {
        try {
            assertEquals(0, this.dataSource.getActiveConnections(), "Repository must return every borrowed connection");
        } finally {
            this.dataSource.dispose();
        }
    }

    @Test
    void returnsNullForAnUnknownUser() {
        assertNull(this.repository.findByUsername("missing"));
        assertNotNull(this.repository.findByUsername("admin"));
    }

    @Test
    void preservesUserFieldsWithoutRoles() throws SQLException {
        this.execute("""
                INSERT INTO user (id, username, display_name, password, enabled)
                VALUES (100, 'alice', 'Alice Example', 'stored-password-hash', false)
                """);

        var user = this.repository.findByUsername("alice");

        assertEquals(100, user.id());
        assertEquals("alice", user.username());
        assertEquals("Alice Example", user.displayName());
        assertEquals("stored-password-hash", user.password());
        assertFalse(user.enabled());
        assertTrue(user.rolePermissionResults().isEmpty());
    }

    @Test
    void groupsPermissionsByRoleAndKeepsRolesWithoutPermissions() throws SQLException {
        this.execute(
                """
                        INSERT INTO user (id, username, display_name, password, enabled)
                        VALUES (100, 'alice', 'Alice', 'hash', true)
                        """,
                """
                        INSERT INTO role (id, code, name)
                        VALUES (10, 'reader', 'Reader'), (20, 'editor', 'Editor'),
                               (30, 'empty', 'Empty'), (40, 'other', 'Other')
                        """,
                """
                        INSERT INTO permission (id, code, name, description)
                        VALUES (10, 'read', 'Read', 'Read messages'), (20, 'write', 'Write', NULL), (30, 'other', 'Other', NULL)
                        """,
                "INSERT INTO user_role (user_id, role_id) VALUES (100, 10), (100, 20), (100, 30), (1, 40)",
                "INSERT INTO role_permission (role_id, permission_id) VALUES (10, 10), (10, 20), (20, 10), (40, 30)");

        var user = this.repository.findByUsername("alice");
        var roles = user.rolePermissionResults();

        assertTrue(user.enabled());
        assertEquals(List.of("reader", "editor", "empty"),
                roles.stream().map(UserRepository.RolePermissionResult::code).toList());
        assertEquals(10, roles.get(0).id());
        assertEquals("Reader", roles.get(0).name());
        assertEquals(List.of("read", "write"), roles.get(0).permissions().stream().map(Permission::getCode).toList());
        assertEquals(10, roles.get(0).permissions().get(0).getId());
        assertEquals("Read", roles.get(0).permissions().get(0).getName());
        assertEquals("Read messages", roles.get(0).permissions().get(0).getDescription());
        assertNull(roles.get(0).permissions().get(1).getDescription());
        assertEquals(List.of("read"), roles.get(1).permissions().stream().map(Permission::getCode).toList());
        assertTrue(roles.get(2).permissions().isEmpty());
    }

    @Test
    void reusesASingleConnectionPoolAcrossLookups() {
        for (int i = 0; i < 5; i++) {
            var user = this.repository.findByUsername("admin");
            assertEquals("admin", user.rolePermissionResults().get(0).permissions().get(0).getCode());
            assertEquals(0, this.dataSource.getActiveConnections());
        }
    }

    @Test
    void returnsTheConnectionWhenThePermissionsQueryFails() throws SQLException {
        this.execute("ALTER TABLE permission DROP COLUMN description");

        var exception = assertThrows(IllegalStateException.class, () -> this.repository.findByUsername("admin"));

        assertInstanceOf(SQLException.class, exception.getCause());
        assertEquals("Unable to load user with roles and permissions", exception.getMessage());
    }

    private void execute(String... statements) throws SQLException {
        try (Connection connection = this.dataSource.getConnection(); Statement statement = connection.createStatement()) {
            for (String sql : statements) {
                statement.execute(sql);
            }
        }
    }
}
