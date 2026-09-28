package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.util.Set;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.runtime.client.authentication.PublicClientAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.client.web.PublicClientAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.DefaultAuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.ClientCredentialsGrant;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web.ClientCredentialsGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web.ClientCredentialsRequestParser;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DefaultDeviceConsentPolicy;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceAuthorizationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceConsentService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.exchange.DeviceCodeExchange;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DeviceCodeExchangeRequestParser;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DeviceCodeGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceAuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceVerificationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.TokenExchangeGrant;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web.TokenExchangeGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web.TokenExchangeRequestParser;
import io.quarkiverse.authorization.server.runtime.introspection.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.introspection.web.OAuth2TokenIntrospectionEndpointHandler;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.revocation.web.OAuth2TokenRevocationEndpointHandler;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class AuthorizationServerDisabledTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(NativeImageResourceAssertions.class,
                            NativeImageResourceAssertions.ResourcesVerifiedBuildItem.class).addClass(UnusedValidator.class)
                            .addClass(BeanLookupEndpoint.class)
                            .addAsResource(
                                    new StringAsset(
                                            "quarkus.authorization-server.enabled=false\n"
                                                    + "quarkus.authorization-server.default-login-page-enabled=true\n"
                                                    + "quarkus.authorization-server.signing.public-key-location=classpath:disabled-key.pem\n"
                                                    + "quarkus.authorization-server.oidc.enabled=true\n"
                                                    + "quarkus.authorization-server.oidc.client-registration.enabled=true\n"
                                                    + "quarkus.authorization-server.client-registration.enabled=true"),
                                    "application.properties"))
            .addBuildChainCustomizer(NativeImageResourceAssertions.verify(Set.of(), Set.of("disabled-key.pem")));

    @Test
    void disablingExtensionDoesNotInstallBrowserDefaultsOrPages() {
        var config = ConfigProvider.getConfig();
        Assertions.assertEquals("/index.html",
                config.getValue("quarkus.http.auth.form.landing-page", String.class));
        Assertions.assertFalse(config.getValue("quarkus.http.auth.form.http-only-cookie", Boolean.class));
        given().get("/login.html").then().statusCode(404);
    }

    @Test
    void disablingExtensionDoesNotInstallSecurityBeans() {
        given().when()
                .get("/authorization-server-beans")
                .then()
                .statusCode(200)
                .body(equalTo("false"));
    }

    @Test
    void disablingExtensionDoesNotInstallTokenEndpoint() {
        given().contentType(ContentType.JSON).body("{}").post("/oauth2/register").then().statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .post("/oauth2/token")
                .then()
                .statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", "device-code")
                .formParam("client_id", "device-client")
                .post("/oauth2/token")
                .then()
                .statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .formParam("subject_token", "subject-token")
                .formParam("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .post("/oauth2/token")
                .then()
                .statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("token", "token")
                .post("/oauth2/introspect")
                .then()
                .statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("token", "token")
                .post("/oauth2/revoke")
                .then()
                .statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "device-client")
                .post("/oauth2/device_authorization")
                .then()
                .statusCode(404);
        given().get("/oauth2/device_verification").then().statusCode(404);
        given().when().get("/oauth2/jwks").then().statusCode(404);
        given().when().get("/oauth2/authorize").then().statusCode(404);
        given().when().get("/.well-known/oauth-authorization-server").then().statusCode(404);
        given().when().get("/.well-known/openid-configuration").then().statusCode(404);
        given().when().get("/connect/register").then().statusCode(404);
        given().contentType(ContentType.JSON)
                .body("{}")
                .post("/connect/register")
                .then()
                .statusCode(404);
    }

    @Path("/authorization-server-beans")
    public static class BeanLookupEndpoint {

        @Inject
        Instance<OAuth2ClientAuthenticationMechanism> mechanism;

        @Inject
        Instance<DefaultAuthorizationConsentPolicy> codePolicies;
        @Inject
        Instance<DefaultDeviceConsentPolicy> devicePolicies;
        @Inject
        Instance<OidcLogoutValidator> oidcPolicies;
        @Inject
        Instance<OidcClientRegistrationValidator> registrationPolicies;
        @Inject
        Instance<ClientCredentialsRequestParser> converter;
        @Inject
        Instance<ClientCredentialsGrant> provider;
        @Inject
        Instance<ClientCredentialsRequestValidator> clientCredentialsValidator;
        @Inject
        Instance<ClientCredentialsGrantHandler> handler;
        @Inject
        Instance<OAuth2TokenIntrospectionAuthenticationProvider> introspectionProvider;
        @Inject
        Instance<OAuth2TokenIntrospectionEndpointHandler> introspectionHandler;
        @Inject
        Instance<OAuth2TokenRevocationAuthenticationProvider> revocationProvider;
        @Inject
        Instance<OAuth2TokenRevocationEndpointHandler> revocationHandler;
        @Inject
        Instance<PublicClientAuthenticationConverter> publicClientConverter;
        @Inject
        Instance<PublicClientAuthenticationProvider> publicClientProvider;
        @Inject
        Instance<DeviceAuthorizationService> deviceRequestProvider;
        @Inject
        Instance<OAuth2DeviceAuthorizationEndpointHandler> deviceEndpointHandler;
        @Inject
        Instance<DeviceVerificationService> deviceVerificationProvider;
        @Inject
        Instance<DeviceConsentService> deviceConsentProvider;
        @Inject
        Instance<OAuth2DeviceVerificationEndpointHandler> deviceVerificationEndpointHandler;
        @Inject
        Instance<DeviceCodeExchangeRequestParser> deviceCodeConverter;
        @Inject
        Instance<DeviceCodeExchange> deviceCodeProvider;
        @Inject
        Instance<DeviceCodeGrantHandler> deviceCodeHandler;
        @Inject
        Instance<TokenExchangeRequestParser> tokenExchangeConverter;
        @Inject
        Instance<TokenExchangeGrant> tokenExchangeProvider;
        @Inject
        Instance<TokenExchangeGrantHandler> tokenExchangeHandler;

        @GET
        @Produces(MediaType.TEXT_PLAIN)
        public boolean installed() {
            return this.codePolicies.isResolvable()
                    || this.devicePolicies.isResolvable()
                    || this.oidcPolicies.isResolvable()
                    || this.registrationPolicies.isResolvable()
                    || this.mechanism.isResolvable()
                    || this.converter.isResolvable()
                    || this.provider.isResolvable()
                    || this.clientCredentialsValidator.isResolvable()
                    || this.handler.isResolvable()
                    || this.introspectionProvider.isResolvable()
                    || this.introspectionHandler.isResolvable()
                    || this.revocationProvider.isResolvable()
                    || this.revocationHandler.isResolvable()
                    || this.publicClientConverter.isResolvable()
                    || this.publicClientProvider.isResolvable()
                    || this.deviceRequestProvider.isResolvable()
                    || this.deviceEndpointHandler.isResolvable()
                    || this.deviceVerificationProvider.isResolvable()
                    || this.deviceConsentProvider.isResolvable()
                    || this.deviceVerificationEndpointHandler.isResolvable()
                    || this.deviceCodeConverter.isResolvable()
                    || this.deviceCodeProvider.isResolvable()
                    || this.deviceCodeHandler.isResolvable()
                    || this.tokenExchangeConverter.isResolvable()
                    || this.tokenExchangeProvider.isResolvable()
                    || this.tokenExchangeHandler.isResolvable();
        }
    }

    @Singleton
    public static class UnusedValidator implements AuthorizationRequestValidator {
        public void validate(AuthorizationRequestContext context) {
            throw new AssertionError("Disabled extension must not consume a validator");
        }
    }
}
