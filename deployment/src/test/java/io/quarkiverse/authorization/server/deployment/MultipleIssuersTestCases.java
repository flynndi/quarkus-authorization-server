package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

import io.vertx.core.json.JsonObject;

abstract class MultipleIssuersTestCases {
    @Test
    void metadataKeysAndTokensUseTheSelectedIssuer() throws Exception {
        for (String tenant : List.of("alpha", "beta")) {
            String issuer = "https://server.example/server/" + tenant;
            given().basePath("").get("/.well-known/oauth-authorization-server/server/" + tenant).then().statusCode(200)
                    .body("issuer", equalTo(issuer)).body("token_endpoint", equalTo(issuer + "/token"))
                    .body("registration_endpoint", equalTo(issuer + "/oauth2/register"))
                    .body("pushed_authorization_request_endpoint", equalTo(issuer + "/oauth2/par"));
            given().get("/" + tenant + "/.well-known/openid-configuration").then().statusCode(200)
                    .body("issuer", equalTo(issuer)).body("registration_endpoint", equalTo(issuer + "/connect/register"));
            String token = MultipleIssuersTestCases.token(tenant);
            assertEquals(issuer, MultipleIssuersTestCases.claims(token).getString("iss"));
            assertTrue(MultipleIssuersTestCases.verify(token, tenant));
            assertFalse(MultipleIssuersTestCases.verify(token, tenant.equals("alpha") ? "beta" : "alpha"));
        }
    }

    @Test
    void unknownIssuerAndForeignCredentialsAreRejected() {
        given().auth().preemptive().basic("shared", "beta-secret").formParam("grant_type", "client_credentials")
                .post("/alpha/token").then().statusCode(401);
        given().auth().preemptive().basic("shared", "alpha-secret").formParam("grant_type", "client_credentials")
                .post("/unknown/token").then().statusCode(404);
        given().basePath("").get("/.well-known/oauth-authorization-server/server/unknown").then().statusCode(404);
        given().get("/unknown/.well-known/openid-configuration").then().statusCode(404);
        given().post("/token").then().statusCode(404);
        given().get("/.well-known/oauth-authorization-server/alpha").then().statusCode(404);
        given().header("Forwarded", "host=attacker.example;proto=https").get("/alpha/.well-known/openid-configuration")
                .then().statusCode(200).body("issuer", equalTo("https://server.example/server/alpha"));
    }

    @Test
    void concurrentWorkerRequestsNeverMixIssuerOrStorage() throws Exception {
        try (var executor = Executors.newFixedThreadPool(6)) {
            var requests = new java.util.ArrayList<Callable<Void>>();
            for (int i = 0; i < 16; i++) {
                String tenant = i % 2 == 0 ? "alpha" : "beta";
                requests.add(() -> {
                    String token = MultipleIssuersTestCases.token(tenant);
                    assertEquals("https://server.example/server/" + tenant,
                            MultipleIssuersTestCases.claims(token).getString("iss"));
                    given().auth().preemptive().basic("shared", tenant + "-secret").formParam("token", token)
                            .post("/" + tenant + "/oauth2/introspect").then().statusCode(200).body("active", equalTo(true));
                    String other = tenant.equals("alpha") ? "beta" : "alpha";
                    given().auth().preemptive().basic("shared", other + "-secret").formParam("token", token)
                            .post("/" + other + "/oauth2/introspect").then().statusCode(200).body("active", equalTo(false));
                    return null;
                });
            }
            for (var result : executor.invokeAll(requests))
                result.get();
        }
    }

    @jakarta.inject.Inject
    @io.smallrye.common.annotation.Identifier("alpha")
    io.quarkiverse.authorization.server.tenant.AuthorizationServerTenant alpha;
    @jakarta.inject.Inject
    @io.smallrye.common.annotation.Identifier("beta")
    io.quarkiverse.authorization.server.tenant.AuthorizationServerTenant beta;
    private static final String REDIRECT = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void loginConsentCodeRefreshAndUserInfoStayWithTheirIssuer() {
        String owner = java.util.UUID.randomUUID().toString();
        var challenge = MultipleIssuersTestCases.authorize("alpha", Map.of());
        challenge.then().statusCode(302).header("Location", endsWith("/server/auth/login"));
        var login = given().redirects().follow(false).cookies(challenge.cookies()).formParam("j_username", owner)
                .formParam("j_password", "password").post("/j_security_check").then().statusCode(302)
                .header("Location", containsString("/server/alpha/authorize")).extract().response();
        var alphaCode = this.approve("alpha", login.cookies());
        MultipleIssuersTestCases.exchange("beta", alphaCode).then().statusCode(400).body("error", equalTo("invalid_grant"));
        var tokens = MultipleIssuersTestCases.exchange("alpha", alphaCode).then().statusCode(200).extract().response();
        String access = tokens.path("access_token");
        String refresh = tokens.path("refresh_token");
        String idToken = tokens.path("id_token");
        assertNotNull(refresh);
        assertEquals("https://server.example/server/alpha", MultipleIssuersTestCases.claims(idToken).getString("iss"));
        given().auth().oauth2(access).get("/alpha/userinfo").then().statusCode(200).body("sub", equalTo(owner));
        given().auth().oauth2(access).get("/beta/userinfo").then().statusCode(401);
        given().auth().preemptive().basic("shared", "beta-secret").formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refresh).post("/beta/token").then().statusCode(400)
                .body("error", equalTo("invalid_grant"));
        idToken = given().auth().preemptive().basic("shared", "alpha-secret").formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refresh).post("/alpha/token").then().statusCode(200).extract().path("id_token");
        // Shared host login does not share consent or the OIDC sid between issuers.
        var betaCode = this.approve("beta", login.cookies());
        String betaIdToken = MultipleIssuersTestCases.exchange("beta", betaCode).then().statusCode(200).extract()
                .path("id_token");
        assertNotEquals(MultipleIssuersTestCases.claims(idToken).getString("sid"),
                MultipleIssuersTestCases.claims(betaIdToken).getString("sid"));
        assertNotNull(this.alpha.consents().findById("same-id", owner));
        assertNotNull(this.beta.consents().findById("same-id", owner));
        given().redirects().follow(false).cookies(login.cookies()).queryParam("id_token_hint", idToken)
                .queryParam("post_logout_redirect_uri", "https://client.example/logout").get("/beta/connect/logout").then()
                .statusCode(400);
        given().redirects().follow(false).cookies(login.cookies()).queryParam("id_token_hint", idToken)
                .queryParam("post_logout_redirect_uri", "https://client.example/logout").get("/alpha/connect/logout")
                .then().statusCode(302).header("Location", equalTo("https://client.example/logout"));
    }

    @Test
    void pushedRequestsAndPendingConsentsCannotBeConsumedByAnotherIssuer() {
        var login = given().redirects().follow(false).formParam("j_username", java.util.UUID.randomUUID().toString())
                .formParam("j_password", "password").post("/j_security_check").then().statusCode(302).extract().response();
        String uri = given().auth().preemptive().basic("shared", "alpha-secret").formParam("response_type", "code")
                .formParam("client_id", "shared").formParam("redirect_uri", REDIRECT).formParam("scope", "openid alpha")
                .formParam("code_challenge", CHALLENGE).formParam("code_challenge_method", "S256")
                .post("/alpha/oauth2/par").then().statusCode(201).extract().path("request_uri");
        given().redirects().follow(false).cookies(login.cookies()).queryParam("client_id", "shared")
                .queryParam("request_uri", uri)
                .get("/beta/authorize").then().statusCode(400);
        var consent = given().redirects().follow(false).cookies(login.cookies()).queryParam("client_id", "shared")
                .queryParam("request_uri", uri).get("/alpha/authorize").then().statusCode(200).extract().response();
        String state = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        given().redirects().follow(false).cookies(login.cookies()).formParam("client_id", "shared").formParam("state", state)
                .formParam("scope", "alpha").formParam("consent_action", "approve").post("/beta/authorize").then()
                .statusCode(400);
        var accepted = given().redirects().follow(false).cookies(login.cookies()).formParam("client_id", "shared")
                .formParam("state", state)
                .formParam("scope", "alpha").formParam("consent_action", "approve").post("/alpha/authorize").then()
                .statusCode(302).extract().response();
        MultipleIssuersTestCases.exchange("alpha", MultipleIssuersTestCases.query(accepted, "code")).then().statusCode(200);
    }

    @Test
    void oauthAndOidcRegistrationTokensStayWithTheirIssuer() {
        String initial = this.initial();
        Map<String, Object> metadata = Map.of("client_name", "registered", "grant_types", List.of("client_credentials"));
        given().auth().oauth2(initial).contentType("application/json").body(metadata).post("/beta/oauth2/register").then()
                .statusCode(401);
        var registered = given().auth().oauth2(initial).contentType("application/json").body(metadata)
                .post("/alpha/oauth2/register")
                .then().statusCode(201).extract().response();
        String client = registered.path("client_id");
        String secret = registered.path("client_secret");
        assertNull(this.beta.clients().findByClientId(client));
        given().auth().preemptive().basic(client, secret).formParam("grant_type", "client_credentials").post("/alpha/token")
                .then().statusCode(200);
        given().auth().preemptive().basic(client, secret).formParam("grant_type", "client_credentials").post("/beta/token")
                .then().statusCode(401);
        given().auth().oauth2(initial).contentType("application/json").body(metadata).post("/alpha/oauth2/register").then()
                .statusCode(401);
        String oidcInitial = this.initial();
        Map<String, Object> oidc = Map.of("client_name", "oidc", "redirect_uris", List.of(REDIRECT));
        given().auth().oauth2(oidcInitial).contentType("application/json").body(oidc).post("/beta/connect/register").then()
                .statusCode(401);
        var result = given().auth().oauth2(oidcInitial).contentType("application/json").body(oidc)
                .post("/alpha/connect/register")
                .then().statusCode(201)
                .body("registration_client_uri", startsWith("https://server.example/server/alpha/connect/register?"))
                .extract().response();
        String registration = result.path("registration_access_token");
        String oidcClient = result.path("client_id");
        given().auth().oauth2(registration).queryParam("client_id", oidcClient).get("/beta/connect/register").then()
                .statusCode(401);
        given().auth().oauth2(registration).queryParam("client_id", oidcClient).get("/alpha/connect/register").then()
                .statusCode(200);
    }

    private String initial() {
        String value = java.util.UUID.randomUUID().toString();
        var scopes = java.util.Set.of("client.create");
        this.alpha.authorizations().save(io.quarkiverse.authorization.server.authorization.OAuth2Authorization
                .withRegisteredClient(this.alpha.clients().findByClientId("shared")).principalName("shared")
                .authorizationGrantType(
                        io.quarkiverse.authorization.server.model.AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(scopes).accessToken(new io.quarkiverse.authorization.server.token.OAuth2AccessToken(
                        io.quarkiverse.authorization.server.token.OAuth2AccessToken.TokenType.BEARER,
                        value, java.time.Instant.now(), java.time.Instant.now().plusSeconds(300), scopes))
                .build());
        return value;
    }

    private String approve(String tenant, Map<String, String> cookies) {
        var consent = MultipleIssuersTestCases.authorize(tenant, cookies).then().statusCode(200).extract().response();
        assertTrue(consent.asString().contains("/server/" + tenant + "/authorize"));
        String state = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        var response = given().redirects().follow(false).cookies(cookies).formParam("client_id", "shared")
                .formParam("state", state)
                .formParam("scope", tenant).formParam("consent_action", "approve").post("/" + tenant + "/authorize")
                .then().statusCode(302).extract().response();
        return MultipleIssuersTestCases.query(response, "code");
    }

    static io.restassured.response.Response authorize(String tenant, Map<String, String> cookies) {
        return given().redirects().follow(false).cookies(cookies).queryParam("response_type", "code")
                .queryParam("client_id", "shared")
                .queryParam("redirect_uri", REDIRECT).queryParam("scope", "openid " + tenant)
                .queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256").get("/" + tenant + "/authorize");
    }

    static io.restassured.response.Response exchange(String tenant, String code) {
        return given().auth().preemptive().basic("shared", tenant + "-secret").formParam("grant_type", "authorization_code")
                .formParam("code", code).formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER)
                .post("/" + tenant + "/token");
    }

    static String query(io.restassured.response.Response response, String name) {
        return java.util.Arrays.stream(java.net.URI.create(response.header("Location")).getRawQuery().split("&"))
                .map(value -> value.split("=", 2)).filter(parts -> name.equals(parts[0]))
                .map(parts -> java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8)).findFirst().orElseThrow();
    }

    @Test
    void clientAssertionAudienceIncludesOnlyTheSelectedIssuer() throws Exception {
        String assertion = ClientAssertionTestSupport.assertion("assertion", "0123456789abcdef0123456789abcdef",
                "https://server.example/server/alpha/token", null);
        given().formParam("client_id", "assertion").formParam("client_assertion", assertion)
                .formParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .formParam("grant_type", "client_credentials").post("/beta/token").then().statusCode(401);
        given().formParam("client_id", "assertion").formParam("client_assertion", assertion)
                .formParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .formParam("grant_type", "client_credentials").post("/alpha/token").then().statusCode(200);
    }

    @Test
    void deviceUrlsAndCodesUseTheSelectedIssuer() {
        var device = given().auth().preemptive().basic("shared", "alpha-secret").formParam("scope", "alpha")
                .post("/alpha/oauth2/device_authorization").then().statusCode(200)
                .body("verification_uri", equalTo("https://server.example/server/alpha/oauth2/device_verification"))
                .extract().response();
        String code = device.path("device_code"), userCode = device.path("user_code");
        var cookies = given().redirects().follow(false).formParam("j_username", java.util.UUID.randomUUID().toString())
                .formParam("j_password", "password").post("/j_security_check").then().statusCode(302).extract().cookies();
        given().auth().preemptive().basic("shared", "beta-secret")
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", code).post("/beta/token").then().statusCode(400)
                .body("error", equalTo("invalid_grant"));
        given().cookies(cookies).queryParam("user_code", userCode).get("/beta/oauth2/device_verification").then()
                .statusCode(400);
        var consent = given().cookies(cookies).queryParam("user_code", userCode).get("/alpha/oauth2/device_verification")
                .then().statusCode(200).body(containsString("/server/alpha/oauth2/device_verification")).extract().response();
        String state = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        given().cookies(cookies).formParam("client_id", "shared").formParam("user_code", userCode).formParam("state", state)
                .formParam("scope", "alpha").formParam("approved", true).post("/alpha/oauth2/device_verification").then()
                .statusCode(200);
        given().auth().preemptive().basic("shared", "alpha-secret")
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", code).post("/alpha/token").then().statusCode(200);
    }

    static String token(String tenant) {
        return given().auth().preemptive().basic("shared", tenant + "-secret").formParam("grant_type", "client_credentials")
                .formParam("scope", tenant).post("/" + tenant + "/token").then().statusCode(200).extract().path("access_token");
    }

    static JsonObject claims(String jwt) {
        return new JsonObject(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    static boolean verify(String token, String tenant) throws Exception {
        Map<String, Object> key = given().get("/" + tenant + "/oauth2/jwks").then().statusCode(200).extract().path("keys[0]");
        JsonWebSignature signature = new JsonWebSignature();
        signature.setCompactSerialization(token);
        signature.setKey(JsonWebKey.Factory.newJwk(key).getKey());
        return signature.verifySignature();
    }
}
