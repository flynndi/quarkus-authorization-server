package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Set;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.RefreshTokenGrant;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.web.RefreshTokenGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.web.RefreshTokenRequestParser;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

class OAuth2RefreshTokenGrantTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String REFRESH_TOKEN = "existing-refresh-token";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example.com
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.refresh-client.client-secret=%s
                                                    quarkus.authorization-server.clients.refresh-client.authorization-grant-types=password,refresh_token
                                                    quarkus.authorization-server.clients.refresh-client.scopes=message.read,message.write
                                                    quarkus.authorization-server.clients.refresh-client.reuse-refresh-tokens=false
                                                    """
                                                    .formatted(CLIENT_SECRET_HASH)),
                                    "application.properties"));

    @Inject
    Instance<RefreshTokenRequestParser> converter;

    @Inject
    Instance<RefreshTokenGrant> provider;

    @Inject
    Instance<RefreshTokenGrantHandler> grantHandler;

    @Inject
    RegisteredClientRepository registeredClientRepository;

    @Inject
    OAuth2AuthorizationService authorizationService;

    @BeforeEach
    void seedRefreshToken() {
        OAuth2Authorization existing = this.authorizationService.findByToken(
                REFRESH_TOKEN, OAuth2TokenType.REFRESH_TOKEN);
        if (existing != null) {
            this.authorizationService.remove(existing);
        }
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("refresh-client");
        Instant issuedAt = Instant.now();
        this.authorizationService.save(
                OAuth2Authorization.withRegisteredClient(registeredClient)
                        .principalName("resource-owner")
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                        .authorizedScopes(Set.of("message.read", "message.write"))
                        .attribute(
                                SecurityIdentity.class.getName(),
                                QuarkusSecurityIdentity.builder()
                                        .setPrincipal(new QuarkusPrincipal("resource-owner"))
                                        .addRoles(Set.of("user"))
                                        .build())
                        .refreshToken(
                                new OAuth2RefreshToken(
                                        REFRESH_TOKEN, issuedAt, issuedAt.plusSeconds(3600)))
                        .build());
    }

    @Test
    void refreshTokenBeansAreInstalledWithTheExtension() {
        assertTrue(
                this.converter.isUnsatisfied(),
                "The HTTP parser is internal, not an application bean");
        assertTrue(this.provider.isResolvable());
        assertTrue(this.grantHandler.isResolvable());
    }

    @Test
    void rotatesRefreshTokenAndRejectsThePreviousValue() {
        Response response = refreshTokenRequest(REFRESH_TOKEN)
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("access_token", notNullValue())
                .body("token_type", equalTo("Bearer"))
                .body("refresh_token", not(equalTo(REFRESH_TOKEN)))
                .body("scope", anyOf(
                        equalTo("message.read message.write"),
                        equalTo("message.write message.read")))
                .extract().response();
        String rotatedRefreshToken = response.jsonPath().getString("refresh_token");

        refreshTokenRequest(REFRESH_TOKEN)
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));

        refreshTokenRequest(rotatedRefreshToken)
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("refresh_token", not(equalTo(rotatedRefreshToken)));
    }

    @Test
    void rejectsScopeEscalationWithoutConsumingTokenAndThenNarrowsScope() {
        refreshTokenRequest(REFRESH_TOKEN)
                .formParam("scope", "messages.admin")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_SCOPE));

        refreshTokenRequest(REFRESH_TOKEN)
                .formParam("scope", "message.read")
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("scope", equalTo("message.read"));
    }

    @Test
    void rejectsMissingRefreshTokenParameter() {
        given()
                .auth().preemptive().basic("refresh-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: refresh_token"));
    }

    private static RequestSpecification refreshTokenRequest(String refreshToken) {
        return given()
                .auth().preemptive().basic("refresh-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken);
    }
}
