package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.password.PasswordGrant;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantRequestParser;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class TokenEndpointTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(
                    new StringAsset(
                            """
                                    quarkus.http.root-path=/api
                                    quarkus.management.enabled=true
                                    quarkus.authorization-server.clients.oauth-client.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                    quarkus.authorization-server.clients.oauth-client.authorization-grant-types=password
                                    """),
                    "application.properties"));

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Inject
    Instance<PasswordGrantRequestParser> passwordAuthenticationConverter;

    @Inject
    Instance<PasswordGrant> passwordAuthenticationProvider;

    @Test
    void passwordGrantBeansAreInstalledWithTheExtension() {
        assertTrue(this.passwordAuthenticationConverter.isUnsatisfied());
        assertTrue(this.passwordAuthenticationProvider.isResolvable());
    }

    @Test
    void handlesPostFormRequestAtSharedEndpoint() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:unsupported")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE))
                .body("error_description", equalTo("OAuth 2.0 Parameter: grant_type"))
                .body("error_uri", equalTo(ERROR_URI));
    }

    @Test
    void rejectsMissingGrantTypeAsInvalidRequest() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("username", "user")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: grant_type"))
                .body("error_uri", equalTo(ERROR_URI));
    }

    @Test
    void rejectsRepeatedGrantTypeAsInvalidRequest() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password", "password")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    @Test
    void rejectsBlankGrantTypeAsInvalidRequest() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", " ")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: grant_type"));
    }

    @Test
    void ignoresOtherHttpMethods() {
        given()
                .when().get("/oauth2/token")
                .then()
                .statusCode(404);
    }

    @Test
    void rejectsJsonRequest() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.JSON)
                .body("{}")
                .when().post("/oauth2/token")
                .then()
                .statusCode(415);
    }

    @Test
    void rejectsRequestWithoutContentType() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .body("grant_type=password")
                .when().post("/oauth2/token")
                .then()
                .statusCode(415);
    }
}
