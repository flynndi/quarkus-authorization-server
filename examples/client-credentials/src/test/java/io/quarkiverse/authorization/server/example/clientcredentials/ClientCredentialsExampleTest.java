package io.quarkiverse.authorization.server.example.clientcredentials;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

/** Exercises the documented happy path against this example's own application. */
@QuarkusTest
public class ClientCredentialsExampleTest {
    @Test
    void completesDocumentedFlow() {
        String access = RestAssured.given().auth().preemptive().basic("machine-client", "machine-secret")
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200).body("token_type", equalTo("Bearer"))
                .body("$", not(hasKey("refresh_token"))).extract().path("access_token");
        RestAssured.given().auth().oauth2(access).get("/api/messages").then().statusCode(200)
                .body("subject", equalTo("machine-client"));
    }
}
