package io.quarkiverse.authorization.server.deployment;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;

class ConfiguredDefaultLoginPageTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(LogoutTestApplication.class,
                    LogoutTestApplication.PasswordProvider.class, LogoutTestApplication.TrustedProvider.class)
                    .addAsResource(new StringAsset("""
                            quarkus.authorization-server.default-login-page-enabled=true
                            quarkus.http.root-path=/server
                            quarkus.http.auth.form.enabled=true
                            quarkus.http.auth.session.encryption-key=default-browser-login-test-key
                            quarkus.http.auth.form.login-page=/server/auth/sign-in
                            quarkus.http.auth.form.error-page=/server/auth/sign-in?error=true
                            quarkus.http.auth.form.post-location=/server/auth/check
                            quarkus.http.auth.form.username-parameter=account
                            quarkus.http.auth.form.password-parameter=secret
                            quarkus.http.auth.form.landing-page=/server/app
                            quarkus.http.auth.form.http-only-cookie=false
                            quarkus.http.auth.form.cookie-same-site=strict
                            quarkus.http.auth.permission.browser.paths=/server/auth/sign-in,/server/auth/check
                            quarkus.http.auth.permission.browser.methods=GET,POST
                            quarkus.http.auth.permission.browser.policy=permit
                            quarkus.http.auth.permission.browser.auth-mechanism=form
                            """), "application.properties"));

    @Test
    void usesQuarkusPageLocationsAndFieldsWithoutAddingRootPathTwice() {
        RestAssured.get("/auth/sign-in").then().statusCode(200)
                .body(Matchers.containsString("action=\"/server/auth/check\""))
                .body(Matchers.containsString("name=\"account\""))
                .body(Matchers.containsString("name=\"secret\""))
                .body(Matchers.not(Matchers.containsString("Invalid username")));
        RestAssured.get("/auth/sign-in?error=true&unrelated=yes").then().statusCode(200)
                .body(Matchers.containsString("Invalid username or password"));
        RestAssured.given().redirects().follow(false).formParam("account", "user").formParam("secret", "wrong")
                .post("/auth/check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/server/auth/sign-in?error=true"));
        var login = RestAssured.given().redirects().follow(false).formParam("account", "user").formParam("secret", "password")
                .post("/auth/check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/server/app")).extract().response();
        Assertions.assertFalse(login.getDetailedCookie("quarkus-credential").isHttpOnly());
        Assertions.assertEquals("Strict", login.getDetailedCookie("quarkus-credential").getSameSite());
        RestAssured.get("/login.html").then().statusCode(404);
    }
}
