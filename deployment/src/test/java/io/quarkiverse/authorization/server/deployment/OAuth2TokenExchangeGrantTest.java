package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.TokenExchangeGrant;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web.TokenExchangeGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web.TokenExchangeRequestParser;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class OAuth2TokenExchangeGrantTest {

    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addClasses(
                                    TestJwtCustomizer.class,
                                    TestOpaqueCustomizer.class)
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.oidc.enabled=true
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.source-jwt.client-secret=%s
                                                    quarkus.authorization-server.clients.source-jwt.authorization-grant-types=password
                                                    quarkus.authorization-server.clients.source-jwt.scopes=message.read
                                                    quarkus.authorization-server.clients.source-reference.client-secret=%s
                                                    quarkus.authorization-server.clients.source-reference.authorization-grant-types=password
                                                    quarkus.authorization-server.clients.source-reference.scopes=message.read
                                                    quarkus.authorization-server.clients.source-reference.access-token-format=reference
                                                    quarkus.authorization-server.clients.actor.client-secret=%s
                                                    quarkus.authorization-server.clients.actor.authorization-grant-types=client_credentials
                                                    quarkus.authorization-server.clients.exchange-jwt.client-secret=%s
                                                    quarkus.authorization-server.clients.exchange-jwt.authorization-grant-types=urn:ietf:params:oauth:grant-type:token-exchange
                                                    quarkus.authorization-server.clients.exchange-jwt.scopes=message.read,message.write
                                                    quarkus.authorization-server.clients.exchange-reference.client-secret=%s
                                                    quarkus.authorization-server.clients.exchange-reference.authorization-grant-types=urn:ietf:params:oauth:grant-type:token-exchange
                                                    quarkus.authorization-server.clients.exchange-reference.scopes=message.read
                                                    quarkus.authorization-server.clients.exchange-reference.access-token-format=reference
                                                    """
                                                    .formatted(
                                                            secretHash(),
                                                            secretHash(),
                                                            secretHash(),
                                                            secretHash(),
                                                            secretHash())),
                                    "application.properties"));

    @Inject
    Instance<TokenExchangeRequestParser> converter;
    @Inject
    Instance<TokenExchangeGrant> provider;
    @Inject
    Instance<TokenExchangeGrantHandler> handler;
    @Inject
    Instance<TokenGrantHandler> handlers;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void installsConfiguredGrantAndPublishesItInBothMetadataDocuments() {
        assertTrue(
                this.converter.isUnsatisfied(),
                "The HTTP parser is internal, not an application bean");
        assertTrue(this.provider.isResolvable());
        assertTrue(this.handler.isResolvable());
        assertTrue(this.handlers.stream().map(TokenGrantHandler::getGrantType)
                .anyMatch(AuthorizationGrantType.TOKEN_EXCHANGE::equals));
        assertTrue(this.clients.findByClientId("exchange-jwt").getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.TOKEN_EXCHANGE));

        for (String discovery : Set.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            given().get(discovery)
                    .then()
                    .statusCode(200)
                    .body(
                            "grant_types_supported",
                            hasItem(AuthorizationGrantType.TOKEN_EXCHANGE.getValue()));
        }

        exchangeRequest("exchange-jwt", "missing-subject", ACCESS_TOKEN_TYPE)
                .post("/oauth2/token").then().statusCode(400)
                .body("error", equalTo("invalid_grant"));
    }

    @Test
    void exchangesLocalSubjectAndActorForJwtWithBuiltInClaimsBeforeApplicationCustomizer() {
        String subjectToken = "subject-jwt-" + UUID.randomUUID();
        String actorToken = "actor-" + UUID.randomUUID();
        OAuth2Authorization subject = saveSubject(
                "source-jwt",
                subjectToken,
                QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal("resource-owner"))
                        .addRoles(Set.of("user"))
                        .build(),
                Map.of("sub", "resource-owner", "may_act", Map.of("sub", "actor")));
        OAuth2Authorization actor = saveActor(actorToken);

        Response response = exchangeRequest("exchange-jwt", subjectToken, ACCESS_TOKEN_TYPE)
                .formParam("actor_token", actorToken)
                .formParam("actor_token_type", ACCESS_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("audience", "audit-api")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .body("access_token", notNullValue())
                .body("issued_token_type", equalTo(ACCESS_TOKEN_TYPE))
                .extract().response();

        String accessToken = response.path("access_token");
        assertEquals(3, accessToken.split("\\.").length);
        OAuth2Authorization exchanged = this.authorizations.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertEquals(
                List.of("messages-api", "audit-api"),
                exchanged.getAccessToken().getClaims().get("aud"));
        assertEquals(Map.of("sub", "actor"), exchanged.getAccessToken().getClaims().get("act"));
        assertEquals(
                true, exchanged.getAccessToken().getClaims().get("application_after_exchange"));
        SecurityIdentity identity = assertInstanceOf(
                SecurityIdentity.class,
                exchanged.getAttribute(SecurityIdentity.class.getName()));
        assertEquals("resource-owner", identity.getPrincipal().getName());
        assertEquals(
                List.of("actor"),
                OAuth2TokenExchangeTokenCustomizers.getActors(identity).stream()
                        .map(actorClaims -> actorClaims.get("sub"))
                        .toList());
        assertTrue(subject.getAccessToken().isActive());
        assertTrue(actor.getAccessToken().isActive());
    }

    @Test
    void exchangesForOpaqueTokenAndPreservesHistoricalActorChain() {
        String subjectToken = "subject-chain-" + UUID.randomUUID();
        SecurityIdentity subjectIdentity = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .addRoles(Set.of("user"))
                .addAttribute(
                        OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE,
                        List.of(Map.of("sub", "previous-actor")))
                .build();
        saveSubject("source-jwt", subjectToken, subjectIdentity, Map.of("sub", "resource-owner"));

        String accessToken = exchangeRequest("exchange-reference", subjectToken, ACCESS_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .body("issued_token_type", equalTo(ACCESS_TOKEN_TYPE))
                .extract().path("access_token");

        assertFalse(accessToken.contains("."));
        OAuth2Authorization exchanged = this.authorizations.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertEquals(List.of("messages-api"), exchanged.getAccessToken().getClaims().get("aud"));
        assertEquals(
                Map.of("sub", "previous-actor"), exchanged.getAccessToken().getClaims().get("act"));
        assertEquals(
                true, exchanged.getAccessToken().getClaims().get("application_after_exchange"));
        SecurityIdentity restored = assertInstanceOf(
                SecurityIdentity.class,
                exchanged.getAttribute(SecurityIdentity.class.getName()));
        assertEquals(
                List.of("previous-actor"),
                OAuth2TokenExchangeTokenCustomizers.getActors(restored).stream()
                        .map(actorClaims -> actorClaims.get("sub"))
                        .toList());
    }

    @Test
    void rejectsRequestedJwtForReferenceOutputAndJwtDeclarationForReferenceInput() {
        String referenceSubject = "reference-subject-" + UUID.randomUUID();
        saveSubject(
                "source-reference",
                referenceSubject,
                QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal("resource-owner"))
                        .addRoles(Set.of("user"))
                        .build(),
                Map.of("sub", "resource-owner"));

        exchangeRequest("exchange-reference", referenceSubject, ACCESS_TOKEN_TYPE)
                .formParam("requested_token_type", JWT_TOKEN_TYPE)
                .post("/oauth2/token").then().statusCode(400)
                .body("error", equalTo("invalid_request"));
        exchangeRequest("exchange-jwt", referenceSubject, JWT_TOKEN_TYPE)
                .post("/oauth2/token").then().statusCode(400)
                .body("error", equalTo("invalid_request"));
    }

    @Test
    void honorsIssuedFormatsAfterSourceClientChangesOverHttp() {
        for (String clientId : List.of("source-jwt", "source-reference")) {
            RegisteredClient original = this.clients.findByClientId(clientId);
            boolean issuedJwt = OAuth2TokenFormat.SELF_CONTAINED.equals(original.getTokenSettings().getAccessTokenFormat());
            String tokenValue = "format-change-" + UUID.randomUUID();
            saveSubject(
                    clientId,
                    tokenValue,
                    QuarkusSecurityIdentity.builder()
                            .setPrincipal(new QuarkusPrincipal("resource-owner"))
                            .addRoles(Set.of("user"))
                            .build(),
                    Map.of("sub", "resource-owner"));
            try {
                this.clients.save(RegisteredClient.from(original).tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(issuedJwt ? OAuth2TokenFormat.REFERENCE : OAuth2TokenFormat.SELF_CONTAINED)
                        .build()).build());
                Response response = exchangeRequest("exchange-jwt", tokenValue, JWT_TOKEN_TYPE)
                        .post("/oauth2/token");
                response.then().statusCode(issuedJwt ? 200 : 400);
                if (!issuedJwt) {
                    response.then().body("error", equalTo("invalid_request"));
                }
                exchangeRequest("exchange-jwt", tokenValue, ACCESS_TOKEN_TYPE).post("/oauth2/token")
                        .then().statusCode(200);
            } finally {
                this.clients.save(original);
            }
        }
    }

    @Test
    void rejectsTokenWithoutIssuedFormatForBothInputTypesOverHttp() {
        OAuth2Authorization incomplete = saveSubject(
                "source-jwt",
                "looks.like.jwt",
                QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal("resource-owner"))
                        .addRoles(Set.of("user"))
                        .build(),
                Map.of("sub", "resource-owner"));
        this.authorizations.save(OAuth2Authorization.from(incomplete).token(incomplete.getAccessToken().getToken(),
                metadata -> metadata.remove(OAuth2TokenFormat.class.getName())).build());

        exchangeRequest("exchange-jwt", "looks.like.jwt", JWT_TOKEN_TYPE).post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        exchangeRequest("exchange-jwt", "looks.like.jwt", ACCESS_TOKEN_TYPE).post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
    }

    private OAuth2Authorization saveSubject(String clientId, String tokenValue, SecurityIdentity identity,
            Map<String, Object> claims) {
        RegisteredClient client = this.clients.findByClientId(clientId);
        Instant issuedAt = Instant.now().minusSeconds(5);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                tokenValue, issuedAt, issuedAt.plusSeconds(600), Set.of("message.read"));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .attribute(SecurityIdentity.class.getName(), identity)
                .token(accessToken, metadata -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
                    metadata.put(OAuth2TokenFormat.class.getName(),
                            client.getTokenSettings().getAccessTokenFormat().getValue());
                })
                .build();
        this.authorizations.save(authorization);
        return authorization;
    }

    private OAuth2Authorization saveActor(String tokenValue) {
        RegisteredClient client = this.clients.findByClientId("actor");
        Instant issuedAt = Instant.now().minusSeconds(5);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                tokenValue, issuedAt, issuedAt.plusSeconds(600), Set.of());
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("actor")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(
                        accessToken,
                        metadata -> {
                            metadata.put(
                                    OAuth2TokenFormat.class.getName(),
                                    client.getTokenSettings()
                                            .getAccessTokenFormat()
                                            .getValue());
                            metadata.put(
                                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                    Map.of("sub", "actor"));
                        })
                .build();
        this.authorizations.save(authorization);
        return authorization;
    }

    private static io.restassured.specification.RequestSpecification exchangeRequest(
            String clientId, String subjectToken, String subjectTokenType) {
        return given().auth().preemptive().basic(clientId, "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", AuthorizationGrantType.TOKEN_EXCHANGE.getValue())
                .formParam("subject_token", subjectToken)
                .formParam("subject_token_type", subjectTokenType);
    }

    private static String secretHash() {
        return BcryptUtil.bcryptHash("client-secret");
    }

    @Singleton
    public static class TestJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
        @Override
        public void customize(JwtEncodingContext context) {
            if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claims(claims -> claims.put("application_after_exchange",
                        claims.containsKey("aud") && claims.containsKey("act")));
            }
        }
    }

    @Singleton
    public static class TestOpaqueCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
        @Override
        public void customize(OAuth2TokenClaimsContext context) {
            if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claims(claims -> claims.put("application_after_exchange",
                        claims.containsKey("aud") && claims.containsKey("act")));
            }
        }
    }
}
