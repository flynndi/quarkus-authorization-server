package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;

class SharedEndpointPathTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::baseApplication)
            .overrideConfigKey("quarkus.authorization-server.jwk-set-endpoint", "/oauth2/token");

    @Test
    void dispatchesSamePathByMethod() {
        RestAssured.given().get("/oauth2/token").then().statusCode(200)
                .body("keys[0].kid", org.hamcrest.Matchers.equalTo("registration-test-key"));
        RestAssured.given().contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "unknown").post("/oauth2/token").then().statusCode(401);
    }
}
