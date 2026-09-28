package io.quarkiverse.authorization.server.deployment;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;

class DefaultBrowserLoginPolicyTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(LogoutTestApplication.class,
                    LogoutTestApplication.PasswordProvider.class, LogoutTestApplication.TrustedProvider.class))
            .overrideConfigKey("quarkus.authorization-server.default-login-page-enabled", "true")
            .overrideConfigKey("quarkus.http.auth.form.enabled", "true")
            .overrideConfigKey("quarkus.http.auth.basic", "true")
            .overrideConfigKey("quarkus.http.auth.session.encryption-key", "browser-login-policy-test-key")
            .overrideConfigKey("quarkus.http.auth.permission.catchall.paths", "/*")
            .overrideConfigKey("quarkus.http.auth.permission.catchall.policy", "authenticated")
            .overrideConfigKey("quarkus.http.auth.permission.catchall.auth-mechanism", "basic")
            .overrideConfigKey("quarkus.http.auth.permission.extra.paths", "/error.html")
            .overrideConfigKey("quarkus.http.auth.permission.extra.methods", "GET")
            .overrideConfigKey("quarkus.http.auth.permission.extra.shared", "true")
            .overrideConfigKey("quarkus.http.auth.permission.extra.policy", "deny");

    @Test
    void exactBrowserPathsSelectFormWhileOtherRequestsKeepTheHostsMechanism() {
        RestAssured.get("/login.html").then().statusCode(200);
        RestAssured.given().redirects().follow(false).get("/unrelated").then().statusCode(401);
        RestAssured.given().auth().preemptive().basic("user", "password").get("/unrelated").then().statusCode(404);
        var login = RestAssured.given().redirects().follow(false)
                .formParam("j_username", "user").formParam("j_password", "password").post("/j_security_check")
                .then().statusCode(302).header("Location", Matchers.endsWith("/login.html")).extract().response();
        RestAssured.given().cookies(login.cookies()).redirects().follow(false).get("/error.html").then().statusCode(403);
    }

    @Test
    void deviceVerificationStillRequiresAUser() {
        RestAssured.given().redirects().follow(false).get("/oauth2/device_verification")
                .then().statusCode(302).header("Location", Matchers.endsWith("/login.html"));
        RestAssured.given().redirects().follow(false).post("/oauth2/device_verification")
                .then().statusCode(302).header("Location", Matchers.endsWith("/login.html"));
    }
}
