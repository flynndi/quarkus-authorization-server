package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.http.Headers;

/** Quarkus REST is present, but these OAuth endpoints remain native Vert.x handlers. */
class OAuth2LazyAuthenticationFailureTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(UserInfoTestApplication::application)
            .overrideConfigKey("quarkus.authorization-server.clients.client.authorization-grant-types",
                    "password,refresh_token,client_credentials")
            .overrideConfigKey("quarkus.http.auth.proactive", "false");

    @Test
    void preservesUserInfoBearerErrorsOnGetAndPost() {
        for (String method : new String[] { "GET", "POST" }) {
            given().header("Authorization", "Bearer unknown").request(method, "/me")
                    .then().statusCode(401).contentType(ContentType.JSON).body("error", equalTo("invalid_token"));
            given().headers(new Headers(new Header("Authorization", "Bearer one"), new Header("Authorization", "Bearer two")))
                    .request(method, "/me").then().statusCode(400).body("error", equalTo("invalid_request"));
        }
    }

    @Test
    void preservesDpopChallengesWithLazyAuthenticationAndConfiguredUserInfoPath() {
        for (String method : new String[] { "GET", "POST" }) {
            given().header("Authorization", "DPoP unknown")
                    .request(method, "/me")
                    .then()
                    .statusCode(401)
                    .contentType(ContentType.JSON)
                    .header(
                            "WWW-Authenticate",
                            equalTo("DPoP algs=\"ES256 RS256\", error=\"invalid_dpop_proof\""))
                    .body("error", equalTo("invalid_dpop_proof"));
            given().header("Authorization", "DPoP unknown")
                    .header("DPoP", "proof", "duplicate")
                    .request(method, "/me")
                    .then()
                    .statusCode(401)
                    .body("error", equalTo("invalid_dpop_proof"));
            given().header("Authorization", "DPoP unknown")
                    .header("DPoP", "malformed")
                    .request(method, "/me")
                    .then()
                    .statusCode(401)
                    .header("WWW-Authenticate", containsString("DPoP"))
                    .body("error", equalTo("invalid_token"));
        }
        given().header("Authorization", "DPoP unknown").get("/elsewhere").then().statusCode(200);
    }

    @Test
    void preservesTokenEndpointClientAuthenticationErrors() {
        for (String grant : new String[] { "password", "client_credentials" }) {
            given().auth().preemptive().basic("client", "wrong-secret").contentType(ContentType.URLENC)
                    .formParam("grant_type", grant).post("/oauth2/token")
                    .then().statusCode(401).contentType(ContentType.JSON)
                    .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                    .body("error", equalTo("invalid_client"));
            given().contentType(ContentType.URLENC).formParam("grant_type", grant).post("/oauth2/token")
                    .then().statusCode(401).body("error", equalTo("invalid_client"));
        }
    }

    @Test
    void clientCredentialsWorksWithLazyAuthenticationAndRestWithoutResourceOwnerLogin() {
        given().auth().preemptive().basic("client", "client-secret").contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials").formParam("scope", "openid")
                .post("/oauth2/token").then().statusCode(200).contentType(ContentType.JSON)
                .body("access_token", notNullValue()).body("scope", equalTo("openid"))
                .body("$", not(hasKey("id_token"))).body("$", not(hasKey("refresh_token")));
    }

    @Test
    void leavesOtherRoutesAndMethodsAlone() {
        given().header("Authorization", "Bearer unknown").get("/elsewhere")
                .then().statusCode(200).body(equalTo("unaffected"));
        given().get("/oauth2/token").then().statusCode(404);
        given().put("/me").then().statusCode(404);
    }
}
