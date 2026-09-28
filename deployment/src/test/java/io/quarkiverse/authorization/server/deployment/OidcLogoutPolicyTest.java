package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.util.List;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutRequestValidator;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutValidator;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class OidcLogoutPolicyTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> UserInfoTestApplication.application(jar)
                            .addClasses(
                                    Policies.class,
                                    PolicyRequestProbe.class,
                                    PolicyRequestProbe.Observations.class));

    @Inject
    PolicyRequestProbe.Observations observations;

    @org.junit.jupiter.api.BeforeEach
    void clearObservations() {
        this.observations.clear();
    }

    @Test
    void logoutValidatorControlsHttpAndReleasesRequestScopeOnSuccessAndFailure() {
        String hint = hint();
        given().redirects()
                .follow(false)
                .queryParam("id_token_hint", hint)
                .queryParam("state", "deny")
                .get("/connect/logout")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        this.observations.assertReleased(List.of("logout-validator"));
        given().redirects()
                .follow(false)
                .queryParam("id_token_hint", hint)
                .get("/connect/logout")
                .then()
                .statusCode(302)
                .header("Location", equalTo("/"));
        this.observations.assertReleased(List.of("logout-validator", "logout-added"));
        given().redirects()
                .follow(false)
                .queryParam("id_token_hint", hint)
                .queryParam("post_logout_redirect_uri", "https://unregistered.example/bye")
                .get("/connect/logout")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
    }

    @Test
    void replacementRedirectPolicyDoesNotDisableIdTokenOrClientBinding() {
        String hint = hint();
        given().redirects()
                .follow(false)
                .queryParam("id_token_hint", hint)
                .queryParam("state", "custom")
                .queryParam("post_logout_redirect_uri", "https://application.example/bye")
                .get("/connect/logout")
                .then()
                .statusCode(302)
                .header("Location", equalTo("https://application.example/bye?state=custom"));
        given().queryParam("id_token_hint", "unknown")
                .queryParam("state", "custom")
                .get("/connect/logout")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_token"));
        given().queryParam("id_token_hint", hint)
                .queryParam("client_id", "different")
                .queryParam("state", "custom")
                .get("/connect/logout")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        this.observations.assertReleased(List.of("logout-validator", "logout-added"));
    }

    private static String hint() {
        return given().auth()
                .preemptive()
                .basic("client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .formParam("scope", "openid")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .extract()
                .path("id_token");
    }

    @Singleton
    public static class Policies {

        @Inject
        PolicyRequestProbe request;
        @Inject
        io.vertx.ext.web.RoutingContext http;

        @jakarta.enterprise.inject.Produces
        @Singleton
        OidcLogoutRequestValidator validator() {
            OidcLogoutRequestValidator base = context -> {
                this.request.visit("logout-validator");
                org.junit.jupiter.api.Assertions.assertEquals(
                        "/api/connect/logout", this.http.request().path());
                String state = context.request().getState();
                if (!"custom".equals(state)) {
                    OidcLogoutValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR.validate(
                            context);
                }
                if ("deny".equals(state)) {
                    throw new OAuth2AuthenticationException(
                            OAuth2ErrorCodes.INVALID_REQUEST);
                }
            };
            return base.andThen(context -> request.visit("logout-added"));
        }
    }
}
