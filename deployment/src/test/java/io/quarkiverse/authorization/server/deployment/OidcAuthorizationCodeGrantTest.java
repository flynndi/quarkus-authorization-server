package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcProviderConfiguration;
import io.quarkiverse.authorization.server.oidc.OidcProviderMetadataCustomizer;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class OidcAuthorizationCodeGrantTest {

    private static final String ISSUER = "https://issuer.example.com/api";
    private static final String REDIRECT = "https://client.example.com/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(
                            ResourceOwnerAuthenticationMechanism.class,
                            ResourceOwnerIdentityProvider.class,
                            TestJwtCustomizer.class,
                            TestProviderConfigurationCustomizer.class)
                            .addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource("rotatedPrivateKey.pem")
                            .addAsResource("rotatedPublicKey.pem")
                            .addAsResource("ecPrivateKey.pem")
                            .addAsResource("ecPublicKey.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.http.root-path=/api
                                                    quarkus.authorization-server.issuer=https://issuer.example.com/api
                                                    quarkus.authorization-server.oidc.enabled=true
                                                    quarkus.authorization-server.authorization-endpoint=/authorize
                                                    quarkus.authorization-server.token-endpoint=/token
                                                    quarkus.authorization-server.jwk-set-endpoint=/keys
                                                    quarkus.authorization-server.signing.active-key-id=ps
                                                    quarkus.authorization-server.signing.keys.rs.algorithm=RS256
                                                    quarkus.authorization-server.signing.keys.rs.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.keys.rs.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.signing.keys.ps.algorithm=PS256
                                                    quarkus.authorization-server.signing.keys.ps.private-key-location=classpath:rotatedPrivateKey.pem
                                                    quarkus.authorization-server.signing.keys.ps.public-key-location=classpath:rotatedPublicKey.pem
                                                    quarkus.authorization-server.signing.keys.ec.algorithm=ES256
                                                    quarkus.authorization-server.signing.keys.ec.private-key-location=classpath:ecPrivateKey.pem
                                                    quarkus.authorization-server.signing.keys.ec.public-key-location=classpath:ecPublicKey.pem
                                                    quarkus.authorization-server.signing.keys.verify.algorithm=PS384
                                                    quarkus.authorization-server.signing.keys.verify.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.public.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.public.authorization-grant-types=authorization_code,refresh_token
                                                    quarkus.authorization-server.clients.public.redirect-uris=https://client.example.com/callback
                                                    quarkus.authorization-server.clients.public.scopes=openid,message.read
                                                    quarkus.authorization-server.clients.confidential.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                                    quarkus.authorization-server.clients.confidential.authorization-grant-types=authorization_code,refresh_token,password
                                                    quarkus.authorization-server.clients.confidential.redirect-uris=https://client.example.com/callback
                                                    quarkus.authorization-server.clients.confidential.scopes=openid,message.read
                                                    quarkus.authorization-server.clients.confidential.reuse-refresh-tokens=false
                                                    quarkus.authorization-server.clients.ec.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.ec.authorization-grant-types=authorization_code
                                                    quarkus.authorization-server.clients.ec.redirect-uris=https://client.example.com/callback
                                                    quarkus.authorization-server.clients.ec.scopes=openid
                                                    quarkus.authorization-server.clients.ec.id-token-signature-algorithm=ES256
                                                    quarkus.authorization-server.clients.bad.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.bad.authorization-grant-types=authorization_code
                                                    quarkus.authorization-server.clients.bad.redirect-uris=https://client.example.com/callback
                                                    quarkus.authorization-server.clients.bad.scopes=openid
                                                    quarkus.authorization-server.clients.bad.id-token-signature-algorithm=ES384
                                                    """),
                                    "application.properties"));

    @Inject
    OAuth2AuthorizationService authorizationService;
    @Inject
    ObjectMapper objectMapper;

    @Test
    void discoversOnlyImplementedCapabilitiesAndAppliesIndependentCustomizer() {
        given().get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("issuer", equalTo(ISSUER))
                .body("authorization_endpoint", equalTo(ISSUER + "/authorize"))
                .body("token_endpoint", equalTo(ISSUER + "/token"))
                .body("jwks_uri", equalTo(ISSUER + "/keys"))
                .body("response_types_supported", contains("code"))
                .body("subject_types_supported", contains("public"))
                .body("scopes_supported", contains("openid"))
                .body(
                        "id_token_signing_alg_values_supported",
                        containsInAnyOrder("RS256", "PS256", "ES256"))
                .body(
                        "token_endpoint_auth_methods_supported",
                        containsInAnyOrder("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt",
                                "none"))
                .body(
                        "grant_types_supported",
                        containsInAnyOrder(
                                "authorization_code",
                                "refresh_token",
                                "password",
                                "client_credentials",
                                AuthorizationGrantType.DEVICE_CODE.getValue(),
                                AuthorizationGrantType.TOKEN_EXCHANGE.getValue()))
                .body("code_challenge_methods_supported", contains("S256"))
                .body("service_documentation", equalTo("https://issuer.example.com/docs"))
                .body("userinfo_endpoint", equalTo(ISSUER + "/userinfo"))
                .body("end_session_endpoint", equalTo(ISSUER + "/connect/logout"))
                .body("$", not(hasKey("registration_endpoint")))
                .body("revocation_endpoint", equalTo(ISSUER + "/oauth2/revoke"))
                .body("revocation_endpoint_auth_methods_supported",
                        contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                .body("introspection_endpoint", equalTo(ISSUER + "/oauth2/introspect"))
                .body(
                        "introspection_endpoint_auth_methods_supported",
                        contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                .body(
                        "device_authorization_endpoint",
                        equalTo(ISSUER + "/oauth2/device_authorization"));
        given().get("/.well-known/oauth-authorization-server")
                .then()
                .statusCode(200)
                .body("$", not(hasKey("service_documentation")));
        given().post("/.well-known/openid-configuration").then().statusCode(404);
    }

    @Test
    void publicOpenidOnlySkipsConsentAndIssuesVerifiableIdTokenWithNonce() throws Exception {
        String code = issueCode("public", "openid", "n+once/=1");
        Response tokens = exchange("public", code, VERIFIER);
        tokens.then()
                .statusCode(200)
                .header("Cache-Control", containsString("no-store"))
                .body("id_token", notNullValue())
                .body("refresh_token", nullValue());
        String idToken = tokens.path("id_token");
        JsonNode claims = claims(idToken);
        assertEquals(ISSUER, claims.get("iss").asText());
        assertEquals("public", claims.get("aud").get(0).asText());
        assertEquals("public", claims.get("azp").asText());
        assertEquals("n+once/=1", claims.get("nonce").asText());
        assertEquals(1800, claims.get("exp").asLong() - claims.get("iat").asLong());
        assertTrue(claims.get("customizer_saw_access_token").asBoolean());
        assertFalse(claims.has("scope"));
        assertFalse(claims.has("nbf"));
        assertFalse(claims.has("auth_time")); // No fabricated login/session information.
        assertFalse(claims.has("sid"));
        verifyWithJwks(idToken, "RS256");
        assertEquals("PS256", part(tokens.path("access_token"), 0).get("alg").asText());
        assertFalse(claims(tokens.path("access_token")).has("nonce"));
        OAuth2Authorization saved = this.authorizationService.findByToken(idToken, new OAuth2TokenType("id_token"));
        assertEquals(saved.getPrincipalName(), claims.get("sub").asText());
        assertEquals("n+once/=1", saved.getToken(OidcIdToken.class).getToken().getNonce());
        assertNull(this.authorizationService.findByToken(idToken, OAuth2TokenType.ACCESS_TOKEN));
        exchange("public", code, VERIFIER)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_grant"));
        assertTrue(
                this.authorizationService.findById(saved.getId()).getAccessToken().isInvalidated());
    }

    @Test
    void appliesClientSignatureAlgorithm() throws Exception {
        String token = exchange("ec", issueCode("ec", "openid", null), VERIFIER)
                .then()
                .statusCode(200)
                .extract()
                .path("id_token");
        verifyWithJwks(token, "ES256");
        assertFalse(claims(token).has("nonce"));
    }

    @Test
    void consentAutoApprovesOpenidAndRefreshPreservesAuthenticationContextWithoutNonce()
            throws Exception {
        String code = issueCode("public", "openid message.read", "consent-nonce");
        String consentIdToken = exchange("public", code, VERIFIER)
                .then()
                .statusCode(200)
                .body("scope", containsString("openid"))
                .body("scope", containsString("message.read"))
                .extract()
                .path("id_token");
        assertEquals("consent-nonce", claims(consentIdToken).get("nonce").asText());

        Response tokens = exchange(
                "confidential",
                issueCode("confidential", "openid message.read", "refresh-nonce"),
                VERIFIER);
        tokens.then().statusCode(200).body("refresh_token", notNullValue());
        String oldIdToken = tokens.path("id_token");
        OAuth2Authorization original = this.authorizationService.findByToken(oldIdToken, new OAuth2TokenType("id_token"));
        // Models authentication information supplied by an application customizer; refresh must not
        // invent a new login.
        Map<String, Object> originalClaims = new java.util.LinkedHashMap<>(original.getToken(OidcIdToken.class).getClaims());
        Instant authenticatedAt = Instant.now().minusSeconds(600).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        originalClaims.put("auth_time", authenticatedAt);
        originalClaims.put("sid", "opaque-session-reference");
        OidcIdToken current = original.getToken(OidcIdToken.class).getToken();
        this.authorizationService.save(
                OAuth2Authorization.from(original)
                        .token(
                                new OidcIdToken(
                                        current.getTokenValue(),
                                        current.getIssuedAt(),
                                        current.getExpiresAt(),
                                        originalClaims),
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                        originalClaims))
                        .build());
        Response refreshed = given().auth()
                .preemptive()
                .basic("confidential", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token"))
                .formParam("scope", "message.read")
                .post("/token");
        refreshed
                .then()
                .statusCode(200)
                .body("scope", equalTo("message.read"))
                .body("refresh_token", not(equalTo(tokens.<String> path("refresh_token"))));
        String newIdToken = refreshed.path("id_token");
        verifyWithJwks(newIdToken, "RS256");
        JsonNode newClaims = claims(newIdToken);
        assertFalse(newClaims.has("nonce"));
        assertEquals(claims(oldIdToken).get("sub"), newClaims.get("sub"));
        assertEquals(authenticatedAt.getEpochSecond(), newClaims.get("auth_time").asLong());
        assertEquals("opaque-session-reference", newClaims.get("sid").asText());
        assertNull(
                this.authorizationService.findByToken(oldIdToken, new OAuth2TokenType("id_token")));
        assertNotNull(
                this.authorizationService.findByToken(newIdToken, new OAuth2TokenType("id_token")));
    }

    @Test
    void rejectsDuplicateNonceMissingRedirectAndWrongPkceWithoutConsumingCode() {
        authorizationRequest("public", "openid")
                .header("user", "alice")
                .queryParam("nonce", "", "other")
                .get("/authorize")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        given().redirects()
                .follow(false)
                .header("user", "alice")
                .queryParam("response_type", "code")
                .queryParam("client_id", "public")
                .queryParam("scope", "openid")
                .get("/authorize")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        String code = issueCode("public", "openid", null);
        exchange("public", code, "wrong-verifier").then().statusCode(400);
        exchange("public", code, VERIFIER).then().statusCode(200).body("id_token", notNullValue());
    }

    @Test
    void signingFailureDoesNotConsumeCodeOrSavePartialTokens() {
        String code = issueCode("bad", "openid", null);
        exchange("bad", code, VERIFIER)
                .then()
                .statusCode(400)
                .body("error", equalTo("server_error"));
        OAuth2Authorization saved = this.authorizationService.findByToken(code, new OAuth2TokenType("code"));
        assertTrue(saved.getAuthorizationCode().isActive());
        assertNull(saved.getAccessToken());
        assertNull(saved.getToken(OidcIdToken.class));
    }

    @Test
    void keepsPlainOAuthRequestsWithoutIdToken() {
        exchange("public", issueCode("public", "message.read", null), VERIFIER)
                .then()
                .statusCode(200)
                .body("id_token", nullValue());
    }

    @Test
    void passwordIssuesAndRefreshesIdTokenUsingResourceOwnerIdentity() throws Exception {
        Response tokens = given().auth()
                .preemptive()
                .basic("confidential", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .formParam("scope", "openid message.read")
                .post("/token");
        tokens.then()
                .statusCode(200)
                .header("Cache-Control", containsString("no-store"))
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .body("id_token", notNullValue());
        String idToken = tokens.path("id_token");
        verifyWithJwks(idToken, "RS256");
        JsonNode claims = claims(idToken);
        assertEquals(ISSUER, claims.get("iss").asText());
        assertEquals("resource-owner", claims.get("sub").asText());
        assertEquals("confidential", claims.get("aud").get(0).asText());
        assertEquals("confidential", claims.get("azp").asText());
        assertEquals(1800, claims.get("exp").asLong() - claims.get("iat").asLong());
        assertTrue(claims.get("customizer_saw_access_token").asBoolean());
        assertTrue(claims.get("customizer_saw_refresh_token").asBoolean());
        assertFalse(claims.has("nonce"));
        assertFalse(claims.has("auth_time"));
        assertFalse(claims.has("sid"));
        assertFalse(claims.has("scope"));
        assertFalse(claims.has("nbf"));
        assertEquals("PS256", part(tokens.path("access_token"), 0).get("alg").asText());
        OAuth2Authorization saved = this.authorizationService.findByToken(idToken, new OAuth2TokenType("id_token"));
        assertNotNull(saved);
        assertEquals(AuthorizationGrantType.PASSWORD, saved.getAuthorizationGrantType());
        assertEquals("resource-owner", saved.getPrincipalName());
        assertEquals(Set.of("openid", "message.read"), saved.getAuthorizedScopes());
        assertEquals(
                saved.getToken(OidcIdToken.class).getToken().getClaims(),
                saved.getToken(OidcIdToken.class).getClaims());

        Response refreshed = given().auth()
                .preemptive()
                .basic("confidential", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token"))
                .formParam("scope", "message.read")
                .post("/token");
        refreshed
                .then()
                .statusCode(200)
                .body("scope", equalTo("message.read"))
                .body("refresh_token", not(equalTo(tokens.<String> path("refresh_token"))));
        String newIdToken = refreshed.path("id_token");
        verifyWithJwks(newIdToken, "RS256");
        assertEquals("resource-owner", claims(newIdToken).get("sub").asText());
        assertFalse(claims(newIdToken).has("nonce"));
        OAuth2Authorization updated = this.authorizationService.findByToken(newIdToken, new OAuth2TokenType("id_token"));
        assertNotNull(updated);
        assertEquals(saved.getId(), updated.getId());
        assertEquals(Set.of("openid", "message.read"), updated.getAuthorizedScopes());
        assertEquals(Set.of("message.read"), updated.getAccessToken().getToken().getScopes());
        assertNull(this.authorizationService.findByToken(idToken, new OAuth2TokenType("id_token")));
    }

    @Test
    void acceptsOpenidPostAuthorizationRequestUsingFormParameters() throws Exception {
        String location = given().redirects()
                .follow(false)
                .header("user", "post-user")
                .contentType(ContentType.URLENC)
                .formParam("response_type", "code")
                .formParam("client_id", "public")
                .formParam("redirect_uri", REDIRECT)
                .formParam("scope", "openid")
                .formParam("nonce", "post-nonce")
                .formParam("code_challenge", CHALLENGE)
                .formParam("code_challenge_method", "S256")
                .post("/authorize?client_id=wrong-client&scope=message.read")
                .then()
                .statusCode(302)
                .extract()
                .header("Location");
        String code = java.util.Arrays.stream(URI.create(location).getRawQuery().split("&"))
                .filter(parameter -> parameter.startsWith("code="))
                .map(
                        parameter -> URLDecoder.decode(
                                parameter.substring(5), StandardCharsets.UTF_8))
                .findFirst()
                .orElseThrow();
        String idToken = exchange("public", code, VERIFIER)
                .then()
                .statusCode(200)
                .extract()
                .path("id_token");
        verifyWithJwks(idToken, "RS256");
        assertEquals("post-user", claims(idToken).get("sub").asText());
        assertEquals("post-nonce", claims(idToken).get("nonce").asText());
    }

    private String issueCode(String client, String scope, String nonce) {
        String user = "user-" + UUID.randomUUID();
        RequestSpecification request = authorizationRequest(client, scope).header("user", user);
        if (nonce != null) {
            request.queryParam("nonce", nonce);
        }
        Response response = request.get("/authorize");
        if (response.statusCode() == 200) {
            String page = response.asString();
            assertFalse(page.contains("value=\"openid\""));
            var matcher = Pattern.compile("name=\"state\" value=\"([^\"]+)\"").matcher(page);
            assertTrue(matcher.find());
            response = given().redirects()
                    .follow(false)
                    .header("user", user)
                    .contentType(ContentType.URLENC)
                    .formParam("client_id", client)
                    .formParam("state", matcher.group(1))
                    .formParam("scope", "message.read")
                    .post("/authorize");
        }
        String location = response.then().statusCode(302).extract().header("Location");
        for (String parameter : URI.create(location).getRawQuery().split("&")) {
            if (parameter.startsWith("code=")) {
                return URLDecoder.decode(parameter.substring(5), StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("Expected authorization code, got " + location);
    }

    private static RequestSpecification authorizationRequest(String client, String scope) {
        return given().redirects()
                .follow(false)
                .queryParam("response_type", "code")
                .queryParam("client_id", client)
                .queryParam("redirect_uri", REDIRECT)
                .queryParam("scope", scope)
                .queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256");
    }

    private static Response exchange(String client, String code, String verifier) {
        RequestSpecification request = given().contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT)
                .formParam("code_verifier", verifier);
        if ("confidential".equals(client)) {
            request.auth().preemptive().basic(client, "client-secret");
        } else {
            request.formParam("client_id", client);
        }
        return request.post("/token");
    }

    private JsonNode claims(String token) throws Exception {
        return part(token, 1);
    }

    private JsonNode part(String token, int index) throws Exception {
        return this.objectMapper.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[index]));
    }

    private void verifyWithJwks(String token, String algorithm) throws Exception {
        JsonNode header = part(token, 0);
        assertEquals(algorithm, header.get("alg").asText());
        JsonNode keys = this.objectMapper.readTree(given().get("/keys").asString()).get("keys");
        JsonNode key = java.util.stream.StreamSupport.stream(keys.spliterator(), false)
                .filter(k -> header.get("kid").equals(k.get("kid")))
                .findFirst()
                .orElseThrow();
        Signature verifier;
        if ("ES256".equals(algorithm)) {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
            verifier.initVerify(
                    KeyFactory.getInstance("EC")
                            .generatePublic(
                                    new ECPublicKeySpec(
                                            new ECPoint(integer(key, "x"), integer(key, "y")),
                                            params.getParameterSpec(ECParameterSpec.class))));
        } else {
            verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(
                    KeyFactory.getInstance("RSA")
                            .generatePublic(
                                    new RSAPublicKeySpec(integer(key, "n"), integer(key, "e"))));
        }
        String[] parts = token.split("\\.");
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])));
    }

    private static BigInteger integer(JsonNode key, String field) {
        return new BigInteger(1, Base64.getUrlDecoder().decode(key.get(field).asText()));
    }

    @Singleton
    public static class ResourceOwnerAuthenticationMechanism
            implements HttpAuthenticationMechanism {
        @Override
        public Uni<SecurityIdentity> authenticate(
                RoutingContext context, IdentityProviderManager manager) {
            String user = context.request().getHeader("user");
            return user == null
                    ? Uni.createFrom().nullItem()
                    : Uni.createFrom()
                            .item(
                                    QuarkusSecurityIdentity.builder()
                                            .setPrincipal(new QuarkusPrincipal(user))
                                            .build());
        }

        @Override
        public Uni<ChallengeData> getChallenge(RoutingContext context) {
            return Uni.createFrom().nullItem();
        }

        @Override
        public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
            return Set.of();
        }

        @Override
        public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
            return Uni.createFrom().nullItem();
        }
    }

    @Singleton
    public static class ResourceOwnerIdentityProvider
            implements IdentityProvider<UsernamePasswordAuthenticationRequest> {
        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(
                UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            if (!"resource-owner".equals(request.getUsername())
                    || !java.util.Arrays.equals(
                            "resource-owner-password".toCharArray(),
                            request.getPassword().getPassword())) {
                return Uni.createFrom()
                        .failure(new io.quarkus.security.AuthenticationFailedException());
            }
            return Uni.createFrom()
                    .item(
                            QuarkusSecurityIdentity.builder()
                                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                                    .build());
        }
    }

    @Singleton
    public static class TestProviderConfigurationCustomizer
            implements OidcProviderMetadataCustomizer {
        @Override
        public void customize(OidcProviderConfiguration.Builder configuration) {
            configuration.claim("service_documentation", "https://issuer.example.com/docs");
        }
    }

    @Singleton
    public static class TestJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
        @Override
        public void customize(JwtEncodingContext context) {
            if ("id_token".equals(context.getTokenType().getValue())) {
                context.getClaims()
                        .claim(
                                "customizer_saw_access_token",
                                context.getAuthorization().getAccessToken() != null);
                context.getClaims()
                        .claim(
                                "customizer_saw_refresh_token",
                                context.getAuthorization().getRefreshToken() != null);
            }
        }
    }
}
