package io.quarkiverse.authorization.server.it.repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkiverse.authorization.server.it.entity.Permission;
import io.quarkiverse.authorization.server.it.entity.User;

@ApplicationScoped
public class UserRepository {

    private static final String SELECT_USER_BY_USERNAME = """
            SELECT id, username, display_name, password, enabled
            FROM user
            WHERE username = ?
            """;

    private static final String SELECT_ROLES_WITH_PERMISSIONS_BY_USER_ID = """
            SELECT
                r.id AS role_id,
                r.code AS role_code,
                r.name AS role_name,
                p.id AS permission_id,
                p.code AS permission_code,
                p.name AS permission_name,
                p.description AS permission_description
            FROM user_role ur
            INNER JOIN role r ON r.id = ur.role_id
            LEFT JOIN role_permission rp ON rp.role_id = r.id
            LEFT JOIN permission p ON p.id = rp.permission_id
            WHERE ur.user_id = ?
            ORDER BY r.id, p.id
            """;

    private final DataSource dataSource;

    public UserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public UserRoleResult findByUsername(String username) {
        try (Connection connection = this.dataSource.getConnection()) {
            User user = UserRepository.findUser(connection, username);
            if (user == null) {
                return null;
            }
            return new UserRoleResult(user.getId(), user.getUsername(), user.getDisplayName(), user.getPassword(),
                    user.isEnabled(), UserRepository.findRolesWithPermissions(connection, user.getId()));
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to load user with roles and permissions", exception);
        }
    }

    private static User findUser(Connection connection, String username) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT_USER_BY_USERNAME)) {
            statement.setString(1, username);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return new User(result.getLong("id"), result.getString("username"), result.getString("display_name"),
                        result.getString("password"), result.getBoolean("enabled"));
            }
        }
    }

    private static List<RolePermissionResult> findRolesWithPermissions(Connection connection, long userId) throws SQLException {
        Map<Long, RolePermissionResult> roles = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(SELECT_ROLES_WITH_PERMISSIONS_BY_USER_ID)) {
            statement.setLong(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    long roleId = result.getLong("role_id");
                    RolePermissionResult role = roles.get(roleId);
                    if (role == null) {
                        role = new RolePermissionResult(roleId, result.getString("role_code"), result.getString("role_name"),
                                new ArrayList<>());
                        roles.put(roleId, role);
                    }
                    Long permissionId = result.getObject("permission_id", Long.class);
                    if (permissionId != null) {
                        role.permissions().add(new Permission(permissionId, result.getString("permission_code"),
                                result.getString("permission_name"), result.getString("permission_description")));
                    }
                }
            }
        }
        return new ArrayList<>(roles.values());
    }

    public record RolePermissionResult(long id, String code, String name, List<Permission> permissions) {
    }

    public record UserRoleResult(long id, String username, String displayName, String password, boolean enabled,
            List<RolePermissionResult> rolePermissionResults) {
    }
}
