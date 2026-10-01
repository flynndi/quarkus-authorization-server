package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class OidcLogoutCookieDomainNoRenewalTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(OidcLogoutTestSupport::application)
            .overrideConfigKey("quarkus.http.auth.form.cookie-domain", "example.com")
            .overrideConfigKey("quarkus.http.auth.form.cookie-path", "/")
            .overrideConfigKey("quarkus.http.auth.form.new-cookie-interval", "1H");

    @Test
    void logoutExpiresDomainCookiesBeforeRenewalIsDue() throws Exception {
        OidcLogoutTestSupport.assertLogoutExpiresCookies(false);
    }
}
