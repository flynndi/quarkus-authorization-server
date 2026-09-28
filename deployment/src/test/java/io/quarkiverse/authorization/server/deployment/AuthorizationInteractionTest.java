package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class AuthorizationInteractionTest extends AbstractAuthorizationInteractionTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> AuthorizationInteractionTestSupport.application(jar, true));

    @org.junit.jupiter.api.Test
    void parIsAbsentAndReferencesAreRejectedWhenDisabled() {
        for (String discovery : java.util.List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            io.restassured.RestAssured.given().get(discovery).then().statusCode(200)
                    .body("$", org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasKey("pushed_authorization_request_endpoint")))
                    .body("$",
                            org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasKey("require_pushed_authorization_requests")));
        }
        io.restassured.RestAssured.given().formParam("client_id", "browser").post("/oauth2/par").then().statusCode(404);
        io.restassured.RestAssured.given().redirects().follow(false).queryParam("client_id", "browser")
                .queryParam("request_uri", "urn:ietf:params:oauth:request_uri:" + "a".repeat(43))
                .get("/authorize").then().statusCode(400).header("Location", org.hamcrest.Matchers.nullValue());
    }
}
