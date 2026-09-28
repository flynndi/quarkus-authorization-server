package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertFalse;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcClientRegistrationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcLogoutEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcProviderConfigurationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoEndpointHandler;
import io.quarkus.test.QuarkusUnitTest;

class OidcDisabledTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.authorization-server.issuer=https://issuer.example
                                            quarkus.authorization-server.oidc.client-registration.enabled=true
                                            quarkus.authorization-server.clients.client.client-authentication-methods=none
                                            quarkus.authorization-server.clients.client.authorization-grant-types=authorization_code
                                            quarkus.authorization-server.clients.client.redirect-uris=https://client.example/callback
                                            """),
                            "application.properties"));

    @Inject
    Instance<OidcProviderConfigurationEndpointHandler> handler;
    @Inject
    Instance<OidcUserInfoEndpointHandler> userInfoHandler;
    @Inject
    Instance<OidcUserInfoAuthenticationMechanism> bearerMechanism;
    @Inject
    Instance<OidcLogoutEndpointHandler> logoutHandler;
    @Inject
    Instance<OidcSessionManager> sessionManager;
    @Inject
    Instance<OidcClientRegistrationEndpointHandler> registrationHandler;

    @Inject
    Instance<OidcLogoutValidator> policies;
    @Inject
    Instance<OidcClientRegistrationValidator> registrationPolicies;

    @Test
    void oidcIsOptInAndDoesNotChangeOAuthMetadata() {
        assertFalse(this.policies.isResolvable());
        assertFalse(this.registrationPolicies.isResolvable());
        assertFalse(this.handler.isResolvable());
        assertFalse(this.userInfoHandler.isResolvable());
        assertFalse(this.bearerMechanism.isResolvable());
        assertFalse(this.logoutHandler.isResolvable());
        assertFalse(this.sessionManager.isResolvable());
        assertFalse(this.registrationHandler.isResolvable());
        given().get("/connect/register").then().statusCode(404);
        given().post("/connect/register").then().statusCode(404);
        given().get("/connect/logout").then().statusCode(404);
        given().post("/connect/logout").then().statusCode(404);
        given().get("/userinfo").then().statusCode(404);
        given().post("/userinfo").then().statusCode(404);
        given().get("/.well-known/openid-configuration").then().statusCode(404);
        given().get("/.well-known/oauth-authorization-server").then().statusCode(200);
    }
}
