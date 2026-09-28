package io.quarkiverse.authorization.server.example.deviceauthorization;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

/** Exercises the documented happy path against this example's own application. */
@QuarkusTest
public class DeviceExampleTest {
    @Test
    void completesDocumentedFlow() {
        var device = RestAssured.given().formParam("client_id", "public-device").formParam("scope", "message.read")
                .post("/oauth2/device_authorization").then().statusCode(200).extract().response();
        var cookies = RestAssured.given().redirects().follow(false)
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
        var page = RestAssured.given().cookies(cookies).queryParam("user_code", device.<String> path("user_code"))
                .get("/oauth2/device_verification").then().statusCode(200).extract().response();
        var form = RestAssured.given().cookies(cookies);
        for (String name : java.util.List.of("client_id", "user_code", "state")) {
            form.formParam(name, page.htmlPath().getString("**.find { it.@name == '" + name + "' }.@value"));
        }
        form.formParam("scope", "message.read").formParam("approved", true)
                .post("/oauth2/device_verification").then().statusCode(200);
        String access = RestAssured.given().formParam("client_id", "public-device")
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", device.<String> path("device_code"))
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
        RestAssured.given().auth().oauth2(access).get("/api/messages").then().statusCode(200)
                .body("subject", equalTo("resource-owner"));
    }
}
