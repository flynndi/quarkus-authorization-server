package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.RFC6265LaxSpec;
import org.apache.http.message.BasicHeader;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

import io.restassured.response.Response;

final class OidcLogoutTestSupport {
    private static final String REDIRECT = "https://client.example/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    static JavaArchive application(JavaArchive jar) {
        return jar
                .addClasses(LogoutTestApplication.class, LogoutTestApplication.PasswordProvider.class,
                        LogoutTestApplication.TrustedProvider.class, OidcLogoutTestSupport.class)
                .addAsResource(
                        new StringAsset(
                                """
                                        quarkus.http.root-path=/api
                                        quarkus.http.auth.form.enabled=true
                                        quarkus.http.auth.form.cookie-name=login
                                        quarkus.http.auth.form.cookie-path=/api
                                        quarkus.http.auth.form.landing-page=
                                        quarkus.http.auth.form.error-page=
                                        quarkus.http.auth.form.login-page=/api/login
                                        quarkus.http.auth.form.new-cookie-interval=0S
                                        quarkus.http.auth.session.encryption-key=oidc-logout-test-encryption-key
                                        quarkus.authorization-server.issuer=http://localhost:8081/api
                                        quarkus.authorization-server.oidc.enabled=true
                                        quarkus.authorization-server.oidc-logout-endpoint=/bye
                                        quarkus.authorization-server.clients.client.client-secret=%s
                                        quarkus.authorization-server.clients.client.authorization-grant-types=authorization_code,refresh_token
                                        quarkus.authorization-server.clients.client.redirect-uris=https://client.example/callback
                                        quarkus.authorization-server.clients.client.post-logout-redirect-uris=https://client.example/bye?existing=1
                                        quarkus.authorization-server.clients.client.scopes=openid,profile
                                        """
                                        .formatted(io.quarkus.elytron.security.common.BcryptUtil.bcryptHash("secret"))),
                        "application.properties");
    }

    static void assertLogoutExpiresCookies(boolean renewalExpected) throws Exception {
        Response login = given().contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "alice").formParam("j_password", "password").post("/j_security_check")
                .then().statusCode(200).extract().response();
        Map<String, String> cookies = login.cookies();
        String hint = OidcLogoutTestSupport.tokens(cookies).path("id_token");

        // A valid session on an invalid logout request is renewed but must not be logged out.
        Response rejected = given().cookies(cookies).queryParam("id_token_hint", "invalid").get("/bye")
                .then().statusCode(400).extract().response();
        for (String name : List.of("login", "login.oidc")) {
            var renewed = rejected.getDetailedCookies().asList().stream()
                    .filter(cookie -> name.equals(cookie.getName())).toList();
            assertEquals(renewalExpected ? 1 : 0, renewed.size());
            if (renewalExpected) {
                assertNotEquals(0, renewed.getFirst().getMaxAge());
            }
        }

        Response logout = given().cookies(cookies).redirects().follow(false).queryParam("id_token_hint", hint)
                .get("/bye").then().statusCode(302).extract().response();
        for (String name : List.of("login", "login.oidc")) {
            var issued = login.getDetailedCookie(name);
            var deleted = logout.getDetailedCookies().asList().stream()
                    .filter(cookie -> name.equals(cookie.getName())).toList();
            // Checking only the first same-name cookie misses a surviving renewal with another domain.
            assertEquals(1, deleted.size(), () -> logout.getHeaders().toString());
            assertEquals(issued.getDomain(), deleted.getFirst().getDomain());
            assertEquals(issued.getPath(), deleted.getFirst().getPath());
            assertEquals(0, deleted.getFirst().getMaxAge());
            assertEquals("", deleted.getFirst().getValue());
        }

        // Apply both real responses to a client cookie store using an origin matching the configured domain.
        BasicCookieStore browser = new BasicCookieStore();
        OidcLogoutTestSupport.storeCookies(browser, login, "/api/j_security_check");
        assertEquals(2, browser.getCookies().size());
        OidcLogoutTestSupport.storeCookies(browser, logout, "/api/bye");
        assertTrue(browser.getCookies().isEmpty());
        given().redirects().follow(false)
                .cookies(browser.getCookies().stream().collect(Collectors.toMap(Cookie::getName, Cookie::getValue)))
                .queryParams(Map.of("response_type", "code", "client_id", "client", "redirect_uri", REDIRECT,
                        "scope", "openid", "code_challenge", CHALLENGE, "code_challenge_method", "S256"))
                .get("/oauth2/authorize").then().statusCode(302).header("Location", containsString("/api/login"));
    }

    private static void storeCookies(BasicCookieStore store, Response response, String path) throws MalformedCookieException {
        var spec = new RFC6265LaxSpec();
        var origin = new CookieOrigin("auth.example.com", 80, path, false);
        for (String header : response.getHeaders().getValues("Set-Cookie")) {
            for (Cookie cookie : spec.parse(new BasicHeader("Set-Cookie", header), origin)) {
                spec.validate(cookie, origin);
                store.addCookie(cookie);
            }
        }
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

}
