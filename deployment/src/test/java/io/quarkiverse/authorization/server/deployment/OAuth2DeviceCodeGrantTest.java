package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
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
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.exchange.DeviceCodeExchange;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DeviceCodeExchangeRequestParser;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DeviceCodeGrantHandler;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

class OAuth2DeviceCodeGrantTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.oidc.enabled=true
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.public-device.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.public-device.authorization-grant-types=urn:ietf:params:oauth:grant-type:device_code,refresh_token
                                                    quarkus.authorization-server.clients.public-device.scopes=message.read
                                                    quarkus.authorization-server.clients.confidential-device.client-secret=%s
                                                    quarkus.authorization-server.clients.confidential-device.authorization-grant-types=urn:ietf:params:oauth:grant-type:device_code,refresh_token
                                                    quarkus.authorization-server.clients.confidential-device.scopes=message.read
                                                    quarkus.authorization-server.clients.confidential-device.access-token-format=reference
                                                    """
                                                    .formatted(CLIENT_SECRET_HASH)),
                                    "application.properties"));

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    Instance<DeviceCodeExchangeRequestParser> converter;
    @Inject
    Instance<DeviceCodeExchange> provider;
    @Inject
    Instance<DeviceCodeGrantHandler> handler;
    @Inject
    Instance<TokenGrantHandler> handlers;

    @Test
    void installsGrantAndPublishesCompletedDeviceCapability() {
        assertTrue(
                this.converter.isUnsatisfied(),
                "The HTTP parser is internal, not an application bean");
        assertTrue(this.provider.isResolvable());
        assertTrue(this.handler.isResolvable());
        assertTrue(this.handlers.stream().map(TokenGrantHandler::getGrantType)
                .anyMatch(AuthorizationGrantType.DEVICE_CODE::equals));

        for (String discovery : Set.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            given().get(discovery).then().statusCode(200)
                    .body("device_authorization_endpoint",
                            equalTo("https://issuer.example/oauth2/device_authorization"))
                    .body("grant_types_supported", org.hamcrest.Matchers.hasItem(
                            AuthorizationGrantType.DEVICE_CODE.getValue()));
        }

        publicTokenRequest("unknown").then().statusCode(400)
                .body("error", equalTo("invalid_grant"));
    }

    @Test
    void publicClientWithoutProofPollsPendingThenReceivesOnlyJwtOnce() {
        Response deviceAuthorization = startPublicDeviceAuthorization();
        String deviceCode = deviceAuthorization.path("device_code");

        publicTokenRequest(deviceCode)
                .then()
                .statusCode(400)
                .body("error", equalTo("authorization_pending"))
                .body(
                        "error_uri",
                        equalTo("https://datatracker.ietf.org/doc/html/rfc8628#section-3.5"));

        approve(deviceCode);
        Response tokenResponse = publicTokenRequest(deviceCode)
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("access_token", notNullValue())
                .body("refresh_token", org.hamcrest.Matchers.nullValue())
                .body("scope", equalTo("message.read"))
                .body("$", not(hasKey("id_token")))
                .extract()
                .response();
        String accessToken = tokenResponse.path("access_token");
        assertEquals(2, accessToken.chars().filter(character -> character == '.').count());

        OAuth2Authorization saved = this.authorizations.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(saved);
        assertEquals("resource-owner", saved.getPrincipalName());
        assertEquals(Set.of("message.read"), saved.getAuthorizedScopes());
        assertTrue(saved.getToken(OAuth2DeviceCode.class).isInvalidated());
        assertTrue(saved.getToken(OAuth2UserCode.class).isInvalidated());
        assertNull(saved.getRefreshToken());
        assertNull(saved.getToken(OidcIdToken.class));

        publicTokenRequest(deviceCode).then().statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.ACCESS_DENIED));
    }

    @Test
    void confidentialClientReceivesOpaqueAccessTokenAndRefreshToken() {
        Response deviceAuthorization = startConfidentialDeviceAuthorization();
        String deviceCode = deviceAuthorization.path("device_code");
        approve(deviceCode);

        Response tokenResponse = confidentialTokenRequest(deviceCode).then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("$", not(hasKey("id_token")))
                .extract().response();
        String accessToken = tokenResponse.path("access_token");
        assertFalse(accessToken.contains("."));
        assertEquals(128, accessToken.length());

        OAuth2Authorization saved = this.authorizations.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertEquals("resource-owner", saved.getAccessToken().getClaims().get("sub"));
        assertEquals(Set.of("message.read"), saved.getAccessToken().getClaims().get("scope"));
    }

    @Test
    void errorResponsesPreserveDeniedExpiredAndCrossClientState() {
        String deniedCode = startPublicDeviceAuthorization().path("device_code");
        reject(deniedCode);
        publicTokenRequest(deniedCode).then().statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.ACCESS_DENIED));

        String expiredCode = startPublicDeviceAuthorization().path("device_code");
        expire(expiredCode);
        publicTokenRequest(expiredCode).then().statusCode(400)
                .body("error", equalTo("expired_token"));
        assertTrue(this.authorizations.findByToken(expiredCode,
                new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE))
                .getToken(OAuth2DeviceCode.class).isInvalidated());

        String confidentialCode = startConfidentialDeviceAuthorization().path("device_code");
        publicTokenRequest(confidentialCode).then().statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));
        OAuth2Authorization crossClient = this.authorizations.findByToken(confidentialCode,
                new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE));
        assertTrue(crossClient.getToken(OAuth2DeviceCode.class).isInvalidated());
        confidentialTokenRequest(confidentialCode).then().statusCode(400)
                .body("error", equalTo("authorization_pending"));
    }

    private Response startPublicDeviceAuthorization() {
        return given().contentType(ContentType.URLENC)
                .formParam("client_id", "public-device")
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization").then().statusCode(200).extract().response();
    }

    private Response startConfidentialDeviceAuthorization() {
        return given().auth().preemptive().basic("confidential-device", "client-secret")
                .contentType(ContentType.URLENC).formParam("scope", "message.read")
                .post("/oauth2/device_authorization").then().statusCode(200).extract().response();
    }

    private static Response publicTokenRequest(String deviceCode) {
        return publicTokenRequestSpec(deviceCode).post("/oauth2/token");
    }

    private static RequestSpecification publicTokenRequestSpec(String deviceCode) {
        return given().contentType(ContentType.URLENC)
                .formParam("grant_type", AuthorizationGrantType.DEVICE_CODE.getValue())
                .formParam("device_code", deviceCode)
                .formParam("client_id", "public-device");
    }

    private static Response confidentialTokenRequest(String deviceCode) {
        return given().auth().preemptive().basic("confidential-device", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", AuthorizationGrantType.DEVICE_CODE.getValue())
                .formParam("device_code", deviceCode)
                .post("/oauth2/token");
    }

    private void approve(String deviceCode) {
        OAuth2Authorization authorization = findByDeviceCode(deviceCode);
        Set<String> scopes = authorization.getAttribute(OAuth2ParameterNames.SCOPE);
        OAuth2UserCode userCode = authorization.getToken(OAuth2UserCode.class).getToken();
        this.authorizations.save(
                OAuth2Authorization.from(authorization)
                        .principalName("resource-owner")
                        .authorizedScopes(scopes)
                        .token(
                                userCode,
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                        true))
                        .attribute(
                                SecurityIdentity.class.getName(),
                                QuarkusSecurityIdentity.builder()
                                        .setPrincipal(new QuarkusPrincipal("resource-owner"))
                                        .addRoles(Set.of("user"))
                                        .build())
                        .attributes(attributes -> attributes.remove(OAuth2ParameterNames.SCOPE))
                        .build());
    }

    private void reject(String deviceCode) {
        OAuth2Authorization authorization = findByDeviceCode(deviceCode);
        this.authorizations.save(OAuth2Authorization.from(authorization)
                .token(authorization.getToken(OAuth2UserCode.class).getToken(), metadata -> metadata.put(
                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
                .token(authorization.getToken(OAuth2DeviceCode.class).getToken(), metadata -> metadata.put(
                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
                .build());
    }

    private void expire(String deviceCode) {
        OAuth2Authorization authorization = findByDeviceCode(deviceCode);
        OAuth2DeviceCode current = authorization.getToken(OAuth2DeviceCode.class).getToken();
        this.authorizations.save(OAuth2Authorization.from(authorization)
                .token(new OAuth2DeviceCode(current.getTokenValue(),
                        Instant.now().minusSeconds(300), Instant.now().minusSeconds(1)))
                .build());
    }

    private OAuth2Authorization findByDeviceCode(String deviceCode) {
        return this.authorizations.findByToken(deviceCode,
                new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE));
    }
}
