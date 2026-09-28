package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Set;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.client.authentication.PublicClientAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.client.web.PublicClientAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceAuthorizationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceAuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class OAuth2DeviceAuthorizationEndpointTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String PASSWORD_CLIENT_SECRET_HASH = "$2y$10$ZgQdJ3httrP2QQBD/6Tyle6WTzcrBmVR7R8Rw4n966J8sctedV4va";
    private static final String DEVICE_PATH = "/device/authorize";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.http.root-path=/api
                                            quarkus.authorization-server.issuer=https://issuer.example/api
                                            quarkus.authorization-server.device-authorization-endpoint=/device/authorize
                                            quarkus.authorization-server.device-verification-endpoint=/device/activate
                                            quarkus.authorization-server.clients.confidential-device.client-secret=%s
                                            quarkus.authorization-server.clients.confidential-device.authorization-grant-types=urn:ietf:params:oauth:grant-type:device_code
                                            quarkus.authorization-server.clients.confidential-device.scopes=message.read,message.write
                                            quarkus.authorization-server.clients.confidential-device.device-code-time-to-live=PT2M
                                            quarkus.authorization-server.clients.public-device.client-authentication-methods=none
                                            quarkus.authorization-server.clients.public-device.authorization-grant-types=urn:ietf:params:oauth:grant-type:device_code
                                            quarkus.authorization-server.clients.public-device.scopes=message.read
                                            quarkus.authorization-server.clients.password-client.client-secret=%s
                                            quarkus.authorization-server.clients.password-client.authorization-grant-types=password
                                            quarkus.authorization-server.clients.public-password.client-authentication-methods=none
                                            quarkus.authorization-server.clients.public-password.authorization-grant-types=password
                                            """
                                            .formatted(
                                                    CLIENT_SECRET_HASH,
                                                    PASSWORD_CLIENT_SECRET_HASH)),
                            "application.properties"));

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    Instance<PublicClientAuthenticationConverter> clientConverter;
    @Inject
    Instance<PublicClientAuthenticationProvider> clientProvider;
    @Inject
    Instance<DeviceAuthorizationService> requestProvider;
    @Inject
    Instance<OAuth2DeviceAuthorizationEndpointHandler> endpointHandler;

    @Test
    void confidentialClientReceivesAndPersistsDeviceAuthorization() {
        Response response = confidentialRequest()
                .formParam("scope", "message.read")
                .post(DEVICE_PATH)
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("device_code", matchesPattern("[A-Za-z0-9_-]{128}"))
                .body(
                        "user_code",
                        matchesPattern(
                                "[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}"))
                .body(
                        "verification_uri",
                        equalTo("https://issuer.example/api/device/activate"))
                .body(
                        "verification_uri_complete",
                        matchesPattern(
                                "https://issuer\\.example/api/device/activate\\?user_code=[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}"))
                .body("expires_in", equalTo(120))
                .body("$", not(hasKey("interval")))
                .body("$", not(hasKey("client_id")))
                .extract()
                .response();

        String deviceCode = response.path("device_code");
        String userCode = response.path("user_code");
        OAuth2Authorization saved = this.authorizations.findByToken(
                deviceCode, new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE));
        assertNotNull(saved);
        assertEquals(saved, this.authorizations.findByToken(
                userCode, new OAuth2TokenType(OAuth2ParameterNames.USER_CODE)));
        assertEquals("confidential-device", saved.getPrincipalName());
        assertEquals(AuthorizationGrantType.DEVICE_CODE, saved.getAuthorizationGrantType());
        assertEquals(Set.of("message.read"), saved.getAttribute(OAuth2ParameterNames.SCOPE));
        assertTrue(saved.getAuthorizedScopes().isEmpty());
        assertNull(saved.getAttribute(io.quarkus.security.identity.SecurityIdentity.class.getName()));
        assertEquals(Duration.ofMinutes(2), Duration.between(
                saved.getToken(OAuth2DeviceCode.class).getToken().getIssuedAt(),
                saved.getToken(OAuth2DeviceCode.class).getToken().getExpiresAt()));
        assertFalse(saved.getToken(OAuth2UserCode.class).isInvalidated());
    }

    @Test
    void publicDeviceClientUsesSharedNoneIdentification() {
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "public-device")
                .formParam("scope", "message.read")
                .post(DEVICE_PATH)
                .then().statusCode(200)
                .body("device_code", notNullValue())
                .body("expires_in", equalTo(300));

        assertTrue(this.clientConverter.isResolvable());
        assertTrue(this.clientProvider.isResolvable());
        assertTrue(this.requestProvider.isResolvable());
        assertTrue(this.endpointHandler.isResolvable());
    }

    @Test
    void rejectsInvalidClientGrantMethodAndScope() {
        given().auth().preemptive().basic("confidential-device", "wrong-secret")
                .contentType(ContentType.URLENC).post(DEVICE_PATH)
                .then().statusCode(401).body("error", equalTo("invalid_client"));
        given().contentType(ContentType.URLENC).formParam("client_id", "confidential-device")
                .post(DEVICE_PATH).then().statusCode(401)
                .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                .body("error", equalTo("invalid_client"));
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "public-password")
                .post(DEVICE_PATH)
                .then()
                .statusCode(400)
                .body("error", equalTo("unauthorized_client"));
        given().contentType(ContentType.URLENC).formParam("client_id", "unknown")
                .post(DEVICE_PATH).then().statusCode(401)
                .body("error", equalTo("invalid_client"));
        given().auth().preemptive().basic("password-client", "token-client-secret")
                .contentType(ContentType.URLENC).post(DEVICE_PATH)
                .then().statusCode(400).body("error", equalTo("unauthorized_client"));
        confidentialRequest().formParam("scope", "message.admin").post(DEVICE_PATH)
                .then().statusCode(400).body("error", equalTo("invalid_scope"));
    }

    @Test
    void validatesFormRequestConfiguredPathAndPublishedMetadata() {
        confidentialRequest().formParam("scope", "message.read", "message.write")
                .post(DEVICE_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"));
        given().auth().preemptive().basic("confidential-device", "client-secret")
                .contentType(ContentType.JSON).body("{}").post(DEVICE_PATH)
                .then().statusCode(415);
        given().get(DEVICE_PATH).then().statusCode(404);
        confidentialRequest().post("/oauth2/device_authorization").then().statusCode(404);
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", AuthorizationGrantType.DEVICE_CODE.getValue())
                .formParam("device_code", "not-issued")
                .formParam("client_id", "public-device")
                .post("/oauth2/token").then().statusCode(400)
                .body("error", equalTo("invalid_grant"));
        given().get("/.well-known/oauth-authorization-server")
                .then()
                .statusCode(200)
                .body(
                        "device_authorization_endpoint",
                        equalTo("https://issuer.example/api/device/authorize"))
                .body(
                        "grant_types_supported",
                        org.hamcrest.Matchers.hasItem(
                                AuthorizationGrantType.DEVICE_CODE.getValue()));
    }

    private static io.restassured.specification.RequestSpecification confidentialRequest() {
        return given().auth().preemptive().basic("confidential-device", "client-secret")
                .contentType(ContentType.URLENC);
    }
}
