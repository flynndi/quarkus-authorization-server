package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import io.quarkus.test.QuarkusUnitTest;

class OidcProviderConfigurationTest {

    @Inject
    Instance<OidcClientRegistrationHttpMessageConverter> registrationConverter;

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset("""
                    quarkus.authorization-server.issuer=https://issuer.example/
                    quarkus.authorization-server.oidc.enabled=true
                    quarkus.authorization-server.clients.client.client-authentication-methods=none
                    quarkus.authorization-server.clients.client.authorization-grant-types=authorization_code
                    quarkus.authorization-server.clients.client.redirect-uris=https://client.example/callback
                    """), "application.properties"));

    @Test
    void assemblesDefaultCustomizerAndDefaultSigningKeyWithoutDoubleSlashes() {
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("issuer", equalTo("https://issuer.example/"))
                .body("token_endpoint", equalTo("https://issuer.example/oauth2/token"))
                .body("introspection_endpoint", equalTo("https://issuer.example/oauth2/introspect"))
                .body("introspection_endpoint_auth_methods_supported",
                        contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                .body("jwks_uri", equalTo("https://issuer.example/oauth2/jwks"))
                .body("id_token_signing_alg_values_supported", contains("RS256"));
    }

    @Test
    void disabledRegistrationDoesNotInstallAnEndpointOrAdvertiseRegistration() {
        assertFalse(this.registrationConverter.isResolvable());
        for (Class<?> type : java.util.List.of(
                io.quarkiverse.authorization.server.runtime.oidc.web.OidcClientRegistrationEndpointHandler.class,
                io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationAuthenticationMechanism.class,
                io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationEndpointRequestMatcher.class,
                io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientRegistrationService.class,
                io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientConfigurationService.class)) {
            assertFalse(io.quarkus.arc.Arc.container().instance(type).isAvailable(), type.getSimpleName());
        }
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("$", not(hasKey("registration_endpoint")));
        given().get("/.well-known/oauth-authorization-server").then().statusCode(200)
                .body("$", not(hasKey("registration_endpoint")));
        given().get("/connect/register").then().statusCode(404);
        given().contentType("application/json").body("{\"redirect_uris\":[\"https://rp.example/callback\"]}")
                .post("/connect/register").then().statusCode(404);
    }
}
