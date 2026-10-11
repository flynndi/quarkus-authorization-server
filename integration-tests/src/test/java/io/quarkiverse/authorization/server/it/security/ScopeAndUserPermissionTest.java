package io.quarkiverse.authorization.server.it.security;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.UUID;

import javax.sql.DataSource;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.quarkiverse.authorization.server.it.repository.UserRepository;
import io.quarkiverse.authorization.server.it.support.OAuthRequests;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.security.PermissionChecker;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.smallrye.common.annotation.Blocking;

/** A test-only resource proves scope and database permissions are independent requirements. */
@QuarkusTest
class ScopeAndUserPermissionTest {

    @Inject
    DataSource dataSource;

    private String username;

    @BeforeEach
    void createUserWithoutPermissions() throws Exception {
        this.username = "permission-test-" + UUID.randomUUID();
        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO user (username, display_name, password, enabled) VALUES (?, ?, ?, true)")) {
            statement.setString(1, this.username);
            statement.setString(2, "Permission test user");
            statement.setString(3, BcryptUtil.bcryptHash("password"));
            statement.executeUpdate();
        }
    }

    @AfterEach
    void deleteTestUser() throws Exception {
        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("DELETE FROM user WHERE username = ?")) {
            statement.setString(1, this.username);
            statement.executeUpdate();
        }
    }

    @ParameterizedTest
    @CsvSource({ "true,true,200", "true,false,403", "false,true,403", "false,false,403" })
    void requiresBothTokenScopeAndUserPermission(boolean hasPermission, boolean hasScope, int expectedStatus) {
        String subject = hasPermission ? "admin" : this.username;
        String scope = hasScope ? "securityIdentity" : "jsonWebToken";
        String token = OAuthRequests.password(subject, "password", scope).post("/oauth2/token")
                .then().statusCode(200).extract().path("access_token");

        RestAssured.given().auth().oauth2(token).get("/api/permission-test").then().statusCode(expectedStatus);
    }

    @Test
    void clientCredentialsScopeDoesNotGrantUserPermissions() {
        String token = OAuthRequests.client().formParam("grant_type", "client_credentials")
                .formParam("scope", "securityIdentity").post("/oauth2/token")
                .then().statusCode(200).extract().path("access_token");

        RestAssured.given().auth().oauth2(token).get("/api/permission-test").then().statusCode(403);
    }

    @Test
    void permissionChangesApplyWithoutIssuingAnotherToken() throws Exception {
        String token = OAuthRequests.password(this.username, "password", "securityIdentity").post("/oauth2/token")
                .then().statusCode(200).extract().path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/permission-test").then().statusCode(403);

        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement grant = connection.prepareStatement("""
                        INSERT INTO user_role (user_id, role_id)
                        SELECT u.id, r.id FROM user u CROSS JOIN role r WHERE u.username = ? AND r.code = 'admin'
                        """);
                PreparedStatement revoke = connection.prepareStatement(
                        "DELETE FROM user_role WHERE user_id = (SELECT id FROM user WHERE username = ?)")) {
            grant.setString(1, this.username);
            grant.executeUpdate();
            RestAssured.given().auth().oauth2(token).get("/api/permission-test").then().statusCode(200);

            revoke.setString(1, this.username);
            revoke.executeUpdate();
            RestAssured.given().auth().oauth2(token).get("/api/permission-test").then().statusCode(403);
        }
    }

    @Test
    void formCookieCannotBypassBearerAuthentication() {
        RestAssured.given().cookies(OAuthRequests.login()).redirects().follow(false)
                .get("/api/permission-test").then().statusCode(401);
    }

    @ApplicationScoped
    @Path("/api/permission-test")
    public static class PermissionTestResource {

        @Inject
        UserRepository users;

        @GET
        @PermissionsAllowed(value = { "securityIdentity", "user-admin-permission" }, inclusive = true)
        public String secured() {
            return "allowed";
        }

        @PermissionChecker("user-admin-permission")
        @Blocking
        public boolean hasUserPermission(SecurityIdentity identity) {
            if (!(identity.getPrincipal() instanceof JsonWebToken token)) {
                return false;
            }
            var user = this.users.findByUsername(token.getSubject());
            return user != null && user.enabled() && user.rolePermissionResults().stream()
                    .flatMap(role -> role.permissions().stream())
                    .anyMatch(permission -> "admin".equals(permission.getCode()));
        }
    }
}
