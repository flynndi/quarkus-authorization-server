package io.quarkiverse.authorization.server.it.support;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import io.quarkiverse.authorization.server.it.config.AuthorizationServerPersistence;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** HTTP helpers shared by in-process and packaged application tests. */
public final class OAuthRequests {

    private OAuthRequests() {
    }

    public static RequestSpecification client() {
        return RestAssured.given().auth().preemptive().basic(
                AuthorizationServerPersistence.CLIENT_ID, AuthorizationServerPersistence.CLIENT_PASSWORD)
                .contentType(ContentType.URLENC);
    }

    public static RequestSpecification password(String username, String password, String scope) {
        return OAuthRequests.client().formParam("grant_type", "password")
                .formParam("username", username).formParam("password", password).formParam("scope", scope);
    }

    public static Response userTokens(String scope) {
        return OAuthRequests.password("admin", "password", scope).post("/oauth2/token")
                .then().statusCode(200).extract().response();
    }

    public static Map<String, String> login() {
        return RestAssured.given().redirects().follow(false)
                .formParam("j_username", "admin").formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
    }

    public static String hidden(Response page, String name) {
        return page.htmlPath().getString("**.find { it.@name == '" + name + "' }.@value");
    }

    public static String query(String location, String name) {
        return Arrays.stream(URI.create(location).getRawQuery().split("&"))
                .filter(parameter -> parameter.startsWith(name + "="))
                .map(parameter -> URLDecoder.decode(parameter.substring(name.length() + 1), StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
    }
}
