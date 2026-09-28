package io.quarkiverse.authorization.server.deployment;

import jakarta.inject.Inject;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;
import io.restassured.RestAssured;

class DefaultBrowserLoginDisabledTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(LogoutTestApplication.class,
                    LogoutTestApplication.PasswordProvider.class, LogoutTestApplication.TrustedProvider.class))
            .overrideConfigKey("quarkus.http.auth.form.enabled", "true")
            .overrideConfigKey("quarkus.http.auth.session.encryption-key", "disabled-browser-login-test-key");

    @Inject
    VertxHttpConfig http;

    @Test
    void preservesHostFormDefaultsWhenTheBuiltInPageIsDisabled() {
        Assertions.assertEquals("/index.html", this.http.auth().form().landingPage().orElseThrow());
        Assertions.assertFalse(this.http.auth().form().httpOnlyCookie());
        Assertions.assertEquals("STRICT", this.http.auth().form().cookieSameSite().name());
        RestAssured.get("/login.html").then().statusCode(404);
        RestAssured.given().redirects().follow(false).formParam("j_username", "user").formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/index.html"));
    }
}
