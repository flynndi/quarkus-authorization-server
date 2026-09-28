package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class OAuthClientRegistrationDefaultsTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::baseApplication)
            .overrideConfigKey("quarkus.authorization-server.oidc.enabled", "false")
            .overrideConfigKey("quarkus.authorization-server.client-registration.enabled", "true")
            .overrideConfigKey("quarkus.authorization-server.client-registration.open-registration-allowed", "true");

    @Test
    void scopesRequireAnExplicitApplicationPolicy() {
        given().contentType(ContentType.JSON)
                .body(Map.of("grant_types", List.of("client_credentials"), "scope", "message.read"))
                .post("/oauth2/register").then().statusCode(400).body("error", equalTo("invalid_scope"));
        given().contentType(ContentType.JSON).body(Map.of("grant_types", List.of("client_credentials")))
                .post("/oauth2/register").then().statusCode(201)
                .body("token_endpoint_auth_method", equalTo("client_secret_basic"));
    }
}
