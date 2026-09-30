package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class OidcLogoutCookieDomainTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(OidcLogoutTestSupport::application)
            .overrideConfigKey("quarkus.http.auth.form.cookie-domain", "example.com");

    @Test
    void logoutExpiresDomainCookiesEvenWhenAuthenticationRenewsThem() throws Exception {
        OidcLogoutTestSupport.assertLogoutExpiresCookies(true);
    }
}
