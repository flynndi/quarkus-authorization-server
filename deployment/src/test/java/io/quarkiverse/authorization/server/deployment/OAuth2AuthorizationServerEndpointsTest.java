package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.metadata.AuthorizationServerMetadataCustomizer;
import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadata;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

class OAuth2AuthorizationServerEndpointsTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(NativeImageResourceAssertions.class,
                            NativeImageResourceAssertions.ResourcesVerifiedBuildItem.class).addClasses(
                                    ResourceOwnerIdentityProvider.class,
                                    TestJwtCustomizer.class,
                                    TestMetadataCustomizer.class)
                            .addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource("rotatedPrivateKey.pem")
                            .addAsResource("rotatedPublicKey.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.http.root-path=/api
                                                    quarkus.authorization-server.issuer=https://issuer.example.com/api
                                                    quarkus.authorization-server.token-endpoint=/auth/token
                                                    quarkus.authorization-server.jwk-set-endpoint=/auth/keys
                                                    quarkus.authorization-server.signing.active-key-id=rotated-key
                                                    quarkus.authorization-server.signing.keys.old-key.algorithm=RS256
                                                    quarkus.authorization-server.signing.keys.old-key.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.signing.keys.rotated-key.algorithm=PS256
                                                    quarkus.authorization-server.signing.keys.rotated-key.private-key-location=classpath:rotatedPrivateKey.pem
                                                    quarkus.authorization-server.signing.keys.rotated-key.public-key-location=classpath:rotatedPublicKey.pem
                                                    quarkus.authorization-server.clients.oauth-client.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                                    quarkus.authorization-server.clients.oauth-client.authorization-grant-types=password
                                                    quarkus.authorization-server.clients.oauth-client.scopes=message.read
                                                    quarkus.authorization-server.clients.oauth-client.access-token-time-to-live=PT2M
                                                    """),
                                    "application.properties"))
            .addBuildChainCustomizer(NativeImageResourceAssertions.verify(
                    Set.of("publicKey.pem", "rotatedPrivateKey.pem", "rotatedPublicKey.pem"), Set.of("privateKey.pem")));

    @Test
    void usesConfiguredEndpointPathsForRouteSecurityMatcherAndMetadata() {
        tokenResponse()
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"))
                .body("expires_in", equalTo(120));

        given().when().post("/oauth2/token").then().statusCode(404);

        given().when()
                .get("/auth/keys")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("keys.size()", equalTo(2))
                .body("keys.kid", containsInAnyOrder("old-key", "rotated-key"))
                .body("keys.alg", containsInAnyOrder("RS256", "PS256"))
                .body("keys.kty", contains("RSA", "RSA"))
                .body("keys[0]", not(hasKey("d")))
                .body("keys[1]", not(hasKey("d")));

        given().when()
                .get("/.well-known/oauth-authorization-server")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("issuer", equalTo("https://issuer.example.com/api"))
                .body("dpop_signing_alg_values_supported", contains("ES256", "RS256"))
                .body(
                        "authorization_endpoint",
                        equalTo("https://issuer.example.com/api/oauth2/authorize"))
                .body(
                        "device_authorization_endpoint",
                        equalTo("https://issuer.example.com/api/oauth2/device_authorization"))
                .body("token_endpoint", equalTo("https://issuer.example.com/api/auth/token"))
                .body("jwks_uri", equalTo("https://issuer.example.com/api/auth/keys"))
                .body(
                        "introspection_endpoint",
                        equalTo("https://issuer.example.com/api/oauth2/introspect"))
                .body(
                        "introspection_endpoint_auth_methods_supported",
                        contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                .body(
                        "revocation_endpoint",
                        equalTo("https://issuer.example.com/api/oauth2/revoke"))
                .body("revocation_endpoint_auth_methods_supported",
                        contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                .body(
                        "grant_types_supported",
                        containsInAnyOrder(
                                "password",
                                "authorization_code",
                                "refresh_token",
                                "client_credentials",
                                AuthorizationGrantType.DEVICE_CODE.getValue(),
                                AuthorizationGrantType.TOKEN_EXCHANGE.getValue()))
                .body("response_types_supported", contains("code"))
                .body(
                        "token_endpoint_auth_methods_supported",
                        containsInAnyOrder("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt",
                                "none"))
                .body("code_challenge_methods_supported", contains("S256"))
                .body("service_documentation", equalTo("https://issuer.example.com/docs"));
    }

    @Test
    void signsJwtWithPublishedJwkAndAppliesCustomizer() throws Exception {
        String accessToken = tokenResponse().then().statusCode(200).extract().path("access_token");
        String[] tokenParts = accessToken.split("\\.");
        assertEquals(3, tokenParts.length);

        JsonObject header = decodePart(tokenParts[0]);
        JsonObject claims = decodePart(tokenParts[1]);
        assertEquals("PS256", header.getString("alg"));
        assertEquals("rotated-key", header.getString("kid"));
        assertEquals("https://issuer.example.com/api", claims.getString("iss"));
        assertEquals("resource-owner", claims.getString("sub"));
        assertEquals(new JsonArray().add("oauth-client"), claims.getJsonArray("aud"));
        assertEquals(new JsonArray().add("message.read"), claims.getJsonArray("scope"));
        assertEquals("customized", claims.getString("custom_claim"));
        assertNotNull(claims.getString("jti"));
        assertNotNull(claims.getLong("iat"));
        assertNotNull(claims.getLong("exp"));
        assertNotNull(claims.getLong("nbf"));
        assertEquals(120L, claims.getLong("exp") - claims.getLong("iat"));

        JsonObject jwkSet = new JsonObject(given().when().get("/auth/keys").asString());
        assertTrue(verifyRsaJwt(accessToken, findJwk(jwkSet, "rotated-key"), "PS256"));
    }

    @Test
    void keepsOldPublicKeyAvailableDuringSigningKeyRotation() throws Exception {
        JsonObject jwkSet = new JsonObject(given().when().get("/auth/keys").asString());
        String oldToken = oldToken();
        String newToken = tokenResponse().then().statusCode(200).extract().path("access_token");

        assertTrue(verifyRsaJwt(oldToken, findJwk(jwkSet, "old-key"), "RS256"));
        assertTrue(verifyRsaJwt(newToken, findJwk(jwkSet, "rotated-key"), "PS256"));
    }

    private static boolean verifyRsaJwt(String token, JsonObject jwk, String algorithm)
            throws Exception {
        String[] tokenParts = token.split("\\.");
        String modulus = jwk.getString("n");
        String exponent = jwk.getString("e");
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                new BigInteger(1, Base64.getUrlDecoder().decode(modulus)),
                new BigInteger(1, Base64.getUrlDecoder().decode(exponent)));
        Signature verifier = "PS256".equals(algorithm)
                ? Signature.getInstance("RSASSA-PSS")
                : Signature.getInstance("SHA256withRSA");
        if ("PS256".equals(algorithm)) {
            verifier.setParameter(
                    new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        }
        verifier.initVerify(KeyFactory.getInstance("RSA").generatePublic(publicKeySpec));
        verifier.update((tokenParts[0] + "." + tokenParts[1]).getBytes(StandardCharsets.US_ASCII));
        return verifier.verify(Base64.getUrlDecoder().decode(tokenParts[2]));
    }

    private static JsonObject findJwk(JsonObject jwkSet, String keyId) {
        return jwkSet.getJsonArray("keys").stream()
                .map(value -> (JsonObject) value)
                .filter(jwk -> keyId.equals(jwk.getString("kid")))
                .findFirst()
                .orElseThrow();
    }

    private static String oldToken() throws Exception {
        String encodedHeader = encode(new JsonObject().put("alg", "RS256").put("kid", "old-key").encode());
        String encodedClaims = encode(new JsonObject().put("sub", "resource-owner").encode());
        String signingInput = encodedHeader + "." + encodedClaims;
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(oldPrivateKey());
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput
                + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }

    private static PrivateKey oldPrivateKey() throws Exception {
        try (InputStream input = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("privateKey.pem")) {
            String pem = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            return KeyUtils.decodePrivateKey(pem);
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void createsUniqueJtiUnderConcurrentTokenRequests() {
        Set<String> tokenIds = ConcurrentHashMap.newKeySet();
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<CompletableFuture<Void>> requests = new ArrayList<>();
            for (int index = 0; index < 24; index++) {
                requests.add(
                        CompletableFuture.runAsync(
                                () -> {
                                    String accessToken = tokenResponse()
                                            .then()
                                            .statusCode(200)
                                            .extract()
                                            .path("access_token");
                                    tokenIds.add(
                                            decodePart(accessToken.split("\\.")[1])
                                                    .getString("jti"));
                                },
                                executor));
            }
            CompletableFuture.allOf(requests.toArray(CompletableFuture[]::new)).join();
        } finally {
            executor.shutdownNow();
        }
        assertEquals(24, tokenIds.size());
    }

    private static Response tokenResponse() {
        return given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .when()
                .post("/auth/token");
    }

    private static JsonObject decodePart(String part) {
        return new JsonObject(
                new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8));
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
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom()
                    .item(
                            QuarkusSecurityIdentity.builder()
                                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                                    .build());
        }
    }

    @Singleton
    public static class TestJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

        @Override
        public void customize(JwtEncodingContext context) {
            context.getClaims().claim("custom_claim", "customized");
        }
    }

    @Singleton
    public static class TestMetadataCustomizer implements AuthorizationServerMetadataCustomizer {

        @Override
        public void customize(OAuth2AuthorizationServerMetadata.Builder metadata) {
            metadata.claim("service_documentation", "https://issuer.example.com/docs");
        }
    }
}
