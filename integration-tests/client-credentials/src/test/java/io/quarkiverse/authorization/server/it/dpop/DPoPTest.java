package io.quarkiverse.authorization.server.it.dpop;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.*;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;

/** Real HTTP tests reused against the packaged JVM; tokens are explicitly seeded fixtures. */
@QuarkusTest
public class DPoPTest {
    static final PublicJsonWebKey KEY;

    static {
        try {
            KEY = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Test
    void jwtAndOpaqueUseOidcBindingAndNativeSecurityIdentity() throws Exception {
        for (var entry : tokens().entrySet()) {
            String token = entry.getValue();
            var claims = claims("GET", "/resource/guarded", token);
            get("guarded", token, sign(KEY, KEY, claims))
                    .then()
                    .statusCode(200)
                    .body("subject", equalTo("dpop-resource-server"))
                    .body("opaque", equalTo(entry.getKey().equals("opaque")));
            given().auth()
                    .preemptive()
                    .basic("dpop-resource-server", "resource-secret")
                    .contentType(ContentType.URLENC)
                    .formParam("token", token)
                    .post("/oauth2/introspect")
                    .then()
                    .statusCode(200)
                    .body("active", equalTo(true))
                    .body("token_type", equalTo("DPoP"))
                    .body("cnf.jkt", equalTo(KEY.calculateBase64urlEncodedThumbprint("SHA-256")));
        }
    }

    @Test
    void nativeOidcBaselineAcceptsReplaysAndMissingOrExpiredProofTime() throws Exception {
        for (String token : tokens().values()) {
            Map<String, Object> claims = claims("GET", "/resource/raw", token);
            String proof = sign(KEY, KEY, claims);
            get("raw", token, proof).then().statusCode(200);
            get("raw", token, proof).then().statusCode(200);
            claims.remove("iat");
            claims.remove("jti");
            get("raw", token, sign(KEY, KEY, claims)).then().statusCode(200);
            claims.put("iat", Instant.now().minusSeconds(3600).getEpochSecond());
            claims.put("jti", UUID.randomUUID().toString());
            get("raw", token, sign(KEY, KEY, claims)).then().statusCode(200);
        }
    }

    @Test
    void augmentorRejectsReplayAndMissingExpiredOrFutureReplayClaims() throws Exception {
        for (String token : tokens().values()) {
            var claims = claims("GET", "/resource/guarded", token);
            String proof = sign(KEY, KEY, claims);
            get("guarded", token, proof).then().statusCode(200);
            get("guarded", token, proof).then().statusCode(401);
            for (String missing : List.of("iat", "jti")) {
                var invalid = claims("GET", "/resource/guarded", token);
                invalid.remove(missing);
                get("guarded", token, sign(KEY, KEY, invalid)).then().statusCode(401);
            }
            for (long seconds : List.of(-120L, 120L)) {
                var invalid = claims("GET", "/resource/guarded", token);
                invalid.put("iat", Instant.now().plusSeconds(seconds).getEpochSecond());
                get("guarded", token, sign(KEY, KEY, invalid)).then().statusCode(401);
            }
        }
    }

    @Test
    void oidcChecksProofBeforeReplayAugmentationAndPreventsBearerDowngrade() throws Exception {
        var other = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        for (String token : tokens().values()) {
            var claims = claims("GET", "/resource/guarded", token);
            String proof = sign(KEY, KEY, claims);
            given().header("Authorization", "DPoP " + token)
                    .get("/resource/guarded")
                    .then()
                    .statusCode(401);
            given().header("Authorization", "Bearer " + token)
                    .header("DPoP", proof)
                    .get("/resource/guarded")
                    .then()
                    .statusCode(401);
            get("guarded", token, sign(other, other, claims)).then().statusCode(401);
            get("guarded", token, sign(other, KEY, claims)).then().statusCode(401);
            var badHash = new LinkedHashMap<>(claims);
            badHash.put("ath", "wrong");
            get("guarded", token, sign(KEY, KEY, badHash)).then().statusCode(401);
            var badMethod = new LinkedHashMap<>(claims);
            badMethod.put("htm", "POST");
            get("guarded", token, sign(KEY, KEY, badMethod)).then().statusCode(401);
            var badUri = new LinkedHashMap<>(claims);
            badUri.put("htu", target("/resource/raw"));
            get("guarded", token, sign(KEY, KEY, badUri)).then().statusCode(401);
            given().header("Authorization", "DPoP " + token)
                    .header("DPoP", proof, proof)
                    .get("/resource/guarded")
                    .then()
                    .statusCode(401);
            // All preceding failures reused this jti; none may consume it before binding succeeds.
            get("guarded", token, proof).then().statusCode(200);
        }
    }

    @Test
    void sharedVerifierUsesActualHttpFactsAndRegistersOnlyAfterExpectedBinding() throws Exception {
        var claims = claims("POST", "/fixture/proof", null);
        String proof = sign(KEY, KEY, claims);
        given().header("DPoP", proof)
                .queryParam("expected_jkt", "wrong")
                .post("/fixture/proof")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_dpop_proof"));
        given().header("DPoP", proof)
                .header("Forwarded", "host=attacker.example;proto=https")
                .post("/fixture/proof")
                .then()
                .statusCode(200);
        given().header("DPoP", proof)
                .post("/fixture/proof")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_dpop_proof"));
        given().contentType(ContentType.URLENC)
                .formParam("dpop_proof", proof)
                .post("/fixture/proof")
                .then()
                .statusCode(400);
        var fresh = claims("POST", "/fixture/proof", null);
        String duplicate = sign(KEY, KEY, fresh);
        given().header("DPoP", duplicate, duplicate).post("/fixture/proof").then().statusCode(400);
        given().header("DPoP", duplicate).post("/fixture/proof").then().statusCode(200);
        fresh.put("htu", "https://attacker.example/fixture/proof");
        given().header("DPoP", sign(KEY, KEY, fresh))
                .header("Forwarded", "host=attacker.example;proto=https")
                .post("/fixture/proof")
                .then()
                .statusCode(400);
    }

    private static Map<String, String> tokens() {
        var response = given().contentType(ContentType.JSON)
                .body(KEY.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))
                .post("/fixture/tokens")
                .then()
                .statusCode(200)
                .extract()
                .response();
        return Map.of(
                "jwt", response.<String> path("jwt"), "opaque", response.<String> path("opaque"));
    }

    private static io.restassured.response.Response get(String mode, String token, String proof) {
        return given().header("Authorization", "DPoP " + token)
                .header("DPoP", proof)
                .get("/resource/" + mode);
    }

    private static Map<String, Object> claims(String method, String path, String accessToken)
            throws Exception {
        var claims = new LinkedHashMap<String, Object>(
                Map.of(
                        "htm",
                        method,
                        "htu",
                        target(path),
                        "iat",
                        Instant.now().getEpochSecond(),
                        "jti",
                        UUID.randomUUID().toString()));
        if (accessToken != null)
            claims.put(
                    "ath",
                    Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(
                                    MessageDigest.getInstance("SHA-256")
                                            .digest(
                                                    accessToken.getBytes(
                                                            StandardCharsets.US_ASCII))));
        return claims;
    }

    private static String target(String path) {
        URI base = URI.create(RestAssured.baseURI);
        int port = base.getPort() == -1 ? RestAssured.port : base.getPort();
        return base.getScheme() + "://" + base.getHost() + (port > 0 ? ":" + port : "") + path;
    }

    private static String sign(
            PublicJsonWebKey signer, PublicJsonWebKey publicKey, Map<String, Object> claims)
            throws Exception {
        JsonWebSignature proof = new JsonWebSignature();
        proof.setAlgorithmHeaderValue("ES256");
        proof.setHeader("typ", "dpop+jwt");
        proof.setHeader("jwk", publicKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        proof.setPayload(JsonUtil.toJson(claims));
        proof.setKey(signer.getPrivateKey());
        return proof.getCompactSerialization();
    }
}
