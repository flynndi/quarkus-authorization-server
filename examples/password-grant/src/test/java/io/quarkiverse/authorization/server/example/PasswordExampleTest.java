package io.quarkiverse.authorization.server.example;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

/** Exercises the documented happy path against this example's own application. */
@QuarkusTest
public class PasswordExampleTest {
    @Test
    void completesDocumentedFlow() {
        String access = RestAssured.given().auth().preemptive().basic("quarkus-authorization-server", "secret")
                .formParam("grant_type", "password").formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password").formParam("scope", "openid profile message.read")
                .post("/oauth2/token").then().statusCode(200).body("token_type", equalTo("Bearer"))
                .extract().path("access_token");
        RestAssured.given().auth().oauth2(access).get("/api/resource").then().statusCode(200)
                .body("subject", equalTo("resource-owner"));
    }
}
