package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.grant.authorizationcode.OAuth2AuthorizationConsentPage;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.DefaultConsentPage;
import io.quarkus.test.QuarkusUnitTest;

class AuthorizationServerConsentServiceTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset(
                    "quarkus.authorization-server.issuer=https://issuer.example.com"),
                    "application.properties"));

    @Inject
    OAuth2AuthorizationConsentService authorizationConsentService;

    @Inject
    OAuth2AuthorizationConsentPage authorizationConsentPage;

    @Test
    void providesInMemoryConsentServiceByDefault() {
        assertInstanceOf(InMemoryOAuth2AuthorizationConsentService.class, this.authorizationConsentService);
        assertInstanceOf(DefaultConsentPage.class, this.authorizationConsentPage);
    }
}
