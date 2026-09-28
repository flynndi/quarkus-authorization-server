package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.inject.Inject;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.http.Headers;
import io.restassured.response.Response;

class OidcUserInfoEndpointTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(UserInfoTestApplication::application);

    @Inject
    OAuth2AuthorizationService service;

    static Response tokens(String scope) {
        return given().auth().preemptive().basic("client", "client-secret").contentType(ContentType.URLENC)
                .formParam("grant_type", "password").formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password").formParam("scope", scope).post("/oauth2/token")
                .then().statusCode(200).extract().response();
    }

    @Test
    void advertisesConfiguredEndpointAndServesGetAndPostWithoutLeakingIdTokenClaims() {
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("userinfo_endpoint", equalTo("https://issuer.example/api/me"));
        String access = tokens("openid profile email address phone").path("access_token");
        for (String method : new String[] { "GET", "POST" }) {
            given().auth().oauth2(access).request(method, "/me").then().statusCode(200).contentType(ContentType.JSON)
                    .header("Cache-Control", equalTo("no-store"))
                    .body("sub", equalTo("resource-owner")).body("name", equalTo("Resource Owner"))
                    .body("email", equalTo("owner@example.com")).body("email_verified", equalTo(true))
                    .body("address.country", equalTo("CN")).body("phone_number", equalTo("+123"))
                    .body("$", not(hasKey("iss"))).body("$", not(hasKey("aud"))).body("$", not(hasKey("private_claim")));
        }
        given().auth().oauth2(access).put("/me").then().statusCode(404);
        given().get("/userinfo").then().statusCode(404);
        given().header("Authorization", "Bearer invalid").get("/elsewhere").then().statusCode(200).body(equalTo("unaffected"));
    }

    @Test
    void advertisesBothSchemesAndRejectsWrongTokenTypesAndMalformedOrDuplicatedHeaders() {
        Response tokens = tokens("openid");
        given().get("/me").then().statusCode(401).header("WWW-Authenticate", equalTo("Bearer, DPoP algs=\"ES256 RS256\""));
        given().auth().preemptive().basic("client", "client-secret").get("/me").then().statusCode(401)
                .header("WWW-Authenticate", containsString("Bearer"));
        for (String token : new String[] { tokens.path("id_token"), tokens.path("refresh_token"), "unknown",
                tokens.<String> path("access_token") + "tampered" }) {
            given().auth().oauth2(token).get("/me").then().statusCode(401).body("error", equalTo("invalid_token"));
        }
        given().header("Authorization", "Bearer two tokens").get("/me").then().statusCode(401);
        given().headers(new Headers(new Header("Authorization", "Bearer one"), new Header("Authorization", "Bearer two")))
                .get("/me").then().statusCode(400).body("error", equalTo("invalid_request"));
        given().queryParam("access_token", tokens.<String> path("access_token")).get("/me").then().statusCode(401);
        given().contentType(ContentType.URLENC).formParam("access_token", tokens.<String> path("access_token"))
                .post("/me").then().statusCode(401);
    }

    @Test
    void refreshScopeNarrowingChangesClaimsAndCanRemoveUserInfoAccess() {
        Response initial = tokens("openid profile email");
        Response refreshed = refresh(initial.path("refresh_token"), "openid email");
        given().auth().oauth2(refreshed.path("access_token")).get("/me").then().statusCode(200)
                .body("sub", equalTo("resource-owner")).body("email", equalTo("owner@example.com"))
                .body("$", not(hasKey("name")));
        given().auth().oauth2(initial.path("access_token")).get("/me").then().statusCode(401);
        Response narrowed = refresh(refreshed.path("refresh_token"), "email");
        given().auth().oauth2(narrowed.path("access_token")).get("/me").then().statusCode(403)
                .header("WWW-Authenticate", containsString("insufficient_scope")).body("error", equalTo("insufficient_scope"));
    }

    @Test
    void respectsStoredExpirationAndRevocationState() {
        String access = tokens("openid").path("access_token");
        OAuth2Authorization authorization = this.service.findByToken(access, OAuth2TokenType.ACCESS_TOKEN);
        this.service.save(OAuth2Authorization.from(authorization).token(authorization.getAccessToken().getToken(),
                metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true)).build());
        given().auth().oauth2(access).get("/me").then().statusCode(401).body("error", equalTo("invalid_token"));
        String expired = tokens("openid").path("access_token");
        OAuth2Authorization original = this.service.findByToken(expired, OAuth2TokenType.ACCESS_TOKEN);
        Instant now = Instant.now();
        this.service.save(OAuth2Authorization.from(original).accessToken(new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, expired, now.minusSeconds(3600), now.minusSeconds(1),
                original.getAccessToken().getToken().getScopes())).build());
        given().auth().oauth2(expired).post("/me").then().statusCode(401).body("error", equalTo("invalid_token"));
    }

    @Test
    void validatesDpopAgainstActualRootPathAndRejectsExpiredStoredToken() throws Exception {
        String access = tokens("openid").path("access_token");
        var key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        var original = this.service.findByToken(access, OAuth2TokenType.ACCESS_TOKEN);
        Instant now = Instant.now();
        var bound = new OAuth2AccessToken(OAuth2AccessToken.TokenType.DPOP, access, now,
                now.plusSeconds(300), Set.of("openid"));
        var claims = new LinkedHashMap<>(original.getAccessToken().getClaims());
        claims.put("cnf", Map.of("jkt", key.calculateBase64urlEncodedThumbprint("SHA-256")));
        this.service.save(OAuth2Authorization.from(original).token(bound,
                metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims)).build());
        for (String method : new String[] { "GET", "POST" }) {
            // The configured issuer is deliberately different from the actual HTTP origin.
            String target = RestAssured.baseURI + ":" + RestAssured.port + "/api/me";
            String proof = userInfoProof(key, method, target, access);
            given().header("Authorization", "DPoP " + access).header("DPoP", proof).request(method, "/me")
                    .then().statusCode(200).body("sub", equalTo("resource-owner"));
            given().header("Authorization", "DPoP " + access).header("DPoP", proof).request(method, "/me")
                    .then().statusCode(401).body("error", equalTo("invalid_dpop_proof"));
        }
        this.service.save(OAuth2Authorization.from(original).token(new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.DPOP, access, now.minusSeconds(60), now.minusSeconds(1),
                Set.of("openid")),
                metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                .build());
        given().header("Authorization", "DPoP " + access).header("DPoP", "invalid-proof")
                .get("/me").then().statusCode(401).body("error", equalTo("invalid_token"));
    }

    private static String userInfoProof(PublicJsonWebKey key, String method, String target, String access)
            throws Exception {
        String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(access.getBytes(StandardCharsets.US_ASCII)));
        var proof = new JsonWebSignature();
        proof.setAlgorithmHeaderValue("ES256");
        proof.setHeader("typ", "dpop+jwt");
        proof.setHeader("jwk", key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        proof.setPayload(JsonUtil.toJson(Map.of("htm", method, "htu", target,
                "iat", Instant.now().getEpochSecond(), "jti", UUID.randomUUID().toString(), "ath", hash)));
        proof.setKey(key.getPrivateKey());
        return proof.getCompactSerialization();
    }

    private static Response refresh(String refreshToken, String scope) {
        return given().auth().preemptive().basic("client", "client-secret").contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token").formParam("refresh_token", refreshToken)
                .formParam("scope", scope).post("/oauth2/token").then().statusCode(200).extract().response();
    }

}
