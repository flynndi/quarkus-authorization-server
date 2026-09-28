package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism;
import io.restassured.response.Response;
import io.vertx.ext.web.RoutingContext;

class OidcLogoutSessionCustomizationTest {
    private static final String REDIRECT = "https://client.example/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(jar -> jar.addClasses(
            LogoutTestApplication.class, LogoutTestApplication.PasswordProvider.class,
            LogoutTestApplication.TrustedProvider.class, ApplicationSessionManager.class)
            .addAsResource(new StringAsset("""
                    quarkus.http.root-path=/api
                    quarkus.http.auth.proactive=false
                    quarkus.http.auth.form.enabled=true
                    quarkus.http.auth.form.landing-page=
                    quarkus.http.auth.form.cookie-name=login
                    quarkus.http.auth.form.cookie-path=/api
                    quarkus.http.auth.session.encryption-key=application-session-test-encryption
                    quarkus.authorization-server.issuer=http://localhost:8081/api
                    quarkus.authorization-server.oidc.enabled=true
                    quarkus.authorization-server.clients.client.client-secret=%s
                    quarkus.authorization-server.clients.client.authorization-grant-types=authorization_code,refresh_token
                    quarkus.authorization-server.clients.client.redirect-uris=https://client.example/callback
                    quarkus.authorization-server.clients.client.scopes=openid,profile
                    """.formatted(io.quarkus.elytron.security.common.BcryptUtil.bcryptHash("secret"))),
                    "application.properties"));

    @Test
    void applicationSessionManagerReplacesFormDefaultAndLogoutResolvesLazyIdentity() {
        Map<String, String> cookies = login("alice");
        assertFalse(cookies.containsKey("login.oidc"));
        String hint = tokens(cookies).path("id_token");
        Map<String, Object> claims = claims(hint);
        assertEquals("application-public-session-id", claims.get("sid"));
        assertEquals(1700000000, ((Number) claims.get("auth_time")).intValue());
        given().cookies(cookies).redirects().follow(false).queryParam("id_token_hint", hint)
                .get("/connect/logout").then().statusCode(302).header("X-Application-Logout", equalTo("alice"));
    }

    static Map<String, String> login(String username) {
        return new LinkedHashMap<>(given().contentType("application/x-www-form-urlencoded").formParam("j_username", username)
                .formParam("j_password", "password").post("/j_security_check")
                .then().statusCode(200).extract().cookies());
    }

    static Response tokens(Map<String, String> cookies) {
        Response response = given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", "client")
                .queryParam("redirect_uri", REDIRECT).queryParam("scope", "openid profile")
                .queryParam("nonce", "request-nonce").queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize")
                .then().statusCode(302).extract().response();
        String query = URI.create(response.header("Location")).getRawQuery();
        String code = java.util.Arrays.stream(query.split("&")).filter(value -> value.startsWith("code="))
                .map(value -> URLDecoder.decode(value.substring(5), StandardCharsets.UTF_8)).findFirst().orElseThrow();
        return given().auth().preemptive().basic("client", "secret").contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code").formParam("code", code).formParam("redirect_uri", REDIRECT)
                .formParam("code_verifier", VERIFIER).post("/oauth2/token").then().statusCode(200).extract().response();
    }

    static Map<String, Object> claims(String jwt) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                    java.util.Base64.getUrlDecoder().decode(jwt.split("\\.")[1]),
                    new com.fasterxml.jackson.core.type.TypeReference<>() {
                    });
        } catch (java.io.IOException exception) {
            throw new AssertionError(exception);
        }
    }

    @Singleton
    public static class ApplicationSessionManager implements OidcSessionManager {
        public SessionInformation getSessionInformation(RoutingContext context, SecurityIdentity principal) {
            return new SessionInformation(principal.getPrincipal().getName(), "application-public-session-id",
                    Instant.ofEpochSecond(1700000000));
        }

        public void logout(RoutingContext context, SecurityIdentity principal) {
            FormAuthenticationMechanism.logout(context);
            context.response().putHeader("X-Application-Logout", principal.getPrincipal().getName());
        }
    }
}
