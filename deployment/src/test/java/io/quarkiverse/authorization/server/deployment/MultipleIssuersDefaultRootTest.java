package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class MultipleIssuersDefaultRootTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> MultipleIssuersTestSupport.application(jar, false))
            .overrideConfigKey("quarkus.http.root-path", "/")
            .overrideConfigKey("quarkus.authorization-server.issuers.alpha", "https://server.example/alpha")
            .overrideConfigKey("quarkus.authorization-server.issuers.beta", "https://server.example/beta")
            .overrideConfigKey("quarkus.authorization-server.oidc.enabled", "false");

    @Test
    void oauthWorksAtDefaultRootWithoutOidc() {
        given().get("/.well-known/oauth-authorization-server/alpha").then().statusCode(200)
                .body("issuer", equalTo("https://server.example/alpha"))
                .body("token_endpoint", equalTo("https://server.example/alpha/token"));
        given().auth().preemptive().basic("shared", "alpha-secret").formParam("grant_type", "client_credentials")
                .formParam("scope", "alpha").post("/alpha/token").then().statusCode(200);
        given().get("/alpha/.well-known/openid-configuration").then().statusCode(404);
    }
}
