package io.quarkiverse.authorization.server.it.registration;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** HTTP-only helpers shared by the application test and the real process-restart test. */
final class ClientRegistrationRequests {
    static final String REDIRECT = "https://rp.example/callback";
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    final String issuer;
    final Map<String, Object> discovery;

    ClientRegistrationRequests(int port) {
        this.issuer = "http://localhost:" + port;
        this.discovery = request().get(this.issuer + "/.well-known/openid-configuration").then().statusCode(200)
                .body("issuer", equalTo(this.issuer)).body("registration_endpoint", equalTo(this.issuer + "/connect/register"))
                .extract().jsonPath().getMap("$");
    }

    RequestSpecification request() {
        return given().baseUri(this.issuer).port(URI.create(this.issuer).getPort()).basePath("").redirects().follow(false);
    }

    String endpoint(String name) {
        return (String) this.discovery.get(name);
    }

    Response post(String token, Object metadata) {
        return request().header("Authorization", "Bearer " + token).contentType(ContentType.JSON).body(metadata)
                .post(endpoint("registration_endpoint"));
    }

    Response register(String initial, boolean publicClient) {
        return post(initial, Map.of("client_name", "Dynamic RP", "redirect_uris", List.of(REDIRECT),
                "post_logout_redirect_uris", List.of("https://rp.example/logged-out"), "scope", "openid",
                "grant_types", List.of("authorization_code", "refresh_token"),
                "token_endpoint_auth_method", publicClient ? "none" : "client_secret_basic"))
                .then().statusCode(201).contentType(ContentType.JSON)
                .header("Cache-Control", equalTo("no-store")).header("Pragma", equalTo("no-cache"))
                .body("token_endpoint_auth_method", equalTo(publicClient ? "none" : "client_secret_basic"))
                .extract().response();
    }

    Response read(Response registration) {
        return request().header("Authorization", "Bearer " + registration.<String> path("registration_access_token"))
                .get(registration.<String> path("registration_client_uri"))
                .then().statusCode(200).header("Cache-Control", equalTo("no-store"))
                .body("client_id", equalTo(registration.path("client_id")))
                .body("client_name", equalTo("Dynamic RP"))
                .body("$", not(hasKey("client_secret"))).body("$", not(hasKey("client_secret_expires_at")))
                .body("$", not(hasKey("registration_access_token"))).extract().response();
    }

    String authorize(Response registration, String nonce) {
        var cookies = request().contentType(ContentType.URLENC)
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
        String location = request().cookies(cookies)
                .queryParam("response_type", "code").queryParam("client_id", registration.<String> path("client_id"))
                .queryParam("redirect_uri", REDIRECT).queryParam("scope", "openid").queryParam("nonce", nonce)
                .queryParam("state", "registration-state").queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256").get(endpoint("authorization_endpoint"))
                .then().statusCode(302).extract().header("Location");
        assertTrue(location.startsWith(REDIRECT + "?"));
        assertEquals("registration-state", query(location, "state"));
        return query(location, "code");
    }

    Response exchange(Response registration, String code) {
        var request = clientRequest(registration).contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code").formParam("code", code)
                .formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER);
        return request.post(endpoint("token_endpoint"));
    }

    RequestSpecification clientRequest(Response registration) {
        var request = request();
        String secret = registration.path("client_secret");
        if (secret == null) {
            request.formParam("client_id", registration.<String> path("client_id"));
        } else {
            request.auth().preemptive().basic(registration.<String> path("client_id"), secret);
        }
        return request;
    }

    Map<String, Object> verifyJwt(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
        Map<String, Object> header = json(parts[0]);
        assertEquals("RS256", header.get("alg"));
        List<Map<String, String>> keys = request().get(endpoint("jwks_uri")).then().statusCode(200).extract().path("keys");
        Map<String, String> key = keys.stream().filter(k -> k.get("kid").equals(header.get("kid"))).findFirst().orElseThrow();
        assertTrue(!key.containsKey("d"));
        var rsa = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, Base64.getUrlDecoder().decode(key.get("n"))),
                new BigInteger(1, Base64.getUrlDecoder().decode(key.get("e")))));
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsa);
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])));
        Map<String, Object> claims = json(parts[1]);
        assertEquals(this.issuer, claims.get("iss"));
        assertTrue(((Number) claims.get("exp")).longValue() > Instant.now().getEpochSecond());
        return claims;
    }

    private static Map<String, Object> json(String encoded) {
        return new JsonPath(new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8)).getMap("$");
    }

    private static String query(String location, String name) {
        for (String part : URI.create(location).getRawQuery().split("&")) {
            String[] pair = part.split("=", 2);
            if (name.equals(pair[0])) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("Missing redirect parameter: " + name);
    }
}
