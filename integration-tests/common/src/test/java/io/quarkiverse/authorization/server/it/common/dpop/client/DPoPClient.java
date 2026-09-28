package io.quarkiverse.authorization.server.it.common.dpop.client;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.*;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** HTTP-only driver shared with packaged and two-process JDBC checks. */
public final class DPoPClient {
    public static final String REDIRECT = "https://client.example/callback";
    public static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private final String base;
    private final int port;

    public DPoPClient() {
        this(null, -1);
    }

    public DPoPClient(String base, int port) {
        this.base = base;
        this.port = port;
    }

    public RequestSpecification request() {
        return RestAssured.given()
                .baseUri(base == null ? RestAssured.baseURI : base)
                .basePath("")
                .port(base == null ? RestAssured.port : port)
                .redirects()
                .follow(false);
    }

    public static PublicJsonWebKey key() throws Exception {
        return EcJwkGenerator.generateJwk(EllipticCurves.P256);
    }

    public static String thumbprint(PublicJsonWebKey key) throws Exception {
        return key.calculateBase64urlEncodedThumbprint("SHA-256");
    }

    public Map<String, String> login() {
        return request()
                .contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner")
                .formParam("j_password", "resource-owner-password")
                .post("/j_security_check")
                .then()
                .statusCode(302)
                .extract()
                .cookies();
    }

    public RequestSpecification authorization(String client, Map<String, String> cookies) {
        return request()
                .cookies(cookies)
                .queryParam("response_type", "code")
                .queryParam("client_id", client)
                .queryParam("redirect_uri", REDIRECT)
                .queryParam("scope", "openid message.read")
                .queryParam("state", "dpop-state")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256");
    }

    public String code(String client, PublicJsonWebKey boundKey) throws Exception {
        var cookies = login();
        var request = authorization(client, cookies);
        if (boundKey != null)
            request.queryParam("dpop_jkt", thumbprint(boundKey));
        Response response = request.get("/oauth2/authorize");
        if (response.statusCode() == 200) {
            var state = Pattern.compile("name=\"state\" value=\"([^\"]+)\"")
                    .matcher(response.asString());
            assertTrue(state.find(), response.asString());
            // Consent must preserve the original dpop_jkt, even if the submitted form changes it.
            response = request()
                    .cookies(cookies)
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("client_id", client)
                    .formParam("state", state.group(1))
                    .formParam("scope", "openid", "message.read")
                    .formParam("dpop_jkt", "ignored-consent-value")
                    .post("/oauth2/authorize");
        }
        response.then().statusCode(302);
        return query(response.header("Location"), "code");
    }

    public RequestSpecification tokenRequest(String client) {
        var request = request().contentType("application/x-www-form-urlencoded");
        if (client.equals("confidential"))
            request.auth().preemptive().basic(client, "confidential-secret");
        else if (client.startsWith("machine-") || client.equals("device-confidential"))
            request.auth().preemptive().basic(client, "grant-secret");
        else
            request.formParam("client_id", client);
        return request;
    }

    public RequestSpecification exchangeRequest(String client, String code) {
        return tokenRequest(client)
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT)
                .formParam("code_verifier", VERIFIER);
    }

    public Response exchange(String client, String code, String proof) {
        var request = exchangeRequest(client, code);
        if (proof != null)
            request.header("DPoP", proof);
        return request.post("/oauth2/token");
    }

    public Response refresh(String client, String refreshToken, String proof) {
        var request = tokenRequest(client)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("scope", "message.read");
        if (proof != null)
            request.header("DPoP", proof);
        return request.post("/oauth2/token");
    }

    public RequestSpecification clientCredentials(String client) {
        return tokenRequest(client)
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read");
    }

    public Response startDevice(String client) {
        return tokenRequest(client)
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization")
                .then()
                .statusCode(200)
                .extract()
                .response();
    }

    public void approveDevice(Response device, boolean approve) {
        var cookies = login();
        var page = request()
                .cookies(cookies)
                .queryParam("user_code", device.<String> path("user_code"))
                .get("/oauth2/device_verification");
        page.then().statusCode(200);
        var form = request().cookies(cookies).contentType("application/x-www-form-urlencoded");
        for (String field : List.of("client_id", "user_code", "state")) {
            var matcher = Pattern.compile("name=\"" + field + "\" value=\"([^\"]+)\"")
                    .matcher(page.asString());
            assertTrue(matcher.find(), "Missing " + field + " in " + page.asString());
            form.formParam(field, matcher.group(1));
        }
        if (approve)
            form.formParam("scope", "message.read");
        form.formParam("approved", approve)
                .post("/oauth2/device_verification")
                .then()
                .statusCode(approve ? 200 : 400);
    }

    public RequestSpecification deviceExchange(String client, String code) {
        return tokenRequest(client)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", code);
    }

    public RequestSpecification tokenExchange(String client, String subject) {
        return tokenRequest(client)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .formParam("subject_token", subject)
                .formParam("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .formParam("scope", "message.read");
    }

    public Response introspect(String token) {
        return request()
                .auth()
                .preemptive()
                .basic("dpop-resource-server", "resource-secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .post("/oauth2/introspect");
    }

    public String proof(PublicJsonWebKey key) throws Exception {
        return proof(key, "POST", "/oauth2/token", null);
    }

    public String proof(PublicJsonWebKey key, String method, String path, String access)
            throws Exception {
        return proof(key, method, path, access, claims -> {
        });
    }

    public String proof(
            PublicJsonWebKey key,
            String method,
            String path,
            String access,
            java.util.function.Consumer<Map<String, Object>> customize)
            throws Exception {
        URI uri = URI.create(base == null ? RestAssured.baseURI : base);
        int targetPort = uri.getPort() == -1 ? (base == null ? RestAssured.port : port) : uri.getPort();
        var claims = new LinkedHashMap<String, Object>(
                Map.of(
                        "htm",
                        method,
                        "htu",
                        uri.getScheme()
                                + "://"
                                + uri.getHost()
                                + (targetPort > 0 ? ":" + targetPort : "")
                                + path,
                        "iat",
                        Instant.now().getEpochSecond(),
                        "jti",
                        UUID.randomUUID().toString()));
        if (access != null)
            claims.put(
                    "ath",
                    Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(
                                    MessageDigest.getInstance("SHA-256")
                                            .digest(access.getBytes(StandardCharsets.US_ASCII))));
        customize.accept(claims);
        JsonWebSignature proof = new JsonWebSignature();
        proof.setAlgorithmHeaderValue("ES256");
        proof.setHeader("typ", "dpop+jwt");
        proof.setHeader("jwk", key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        proof.setPayload(JsonUtil.toJson(claims));
        proof.setKey(key.getPrivateKey());
        return proof.getCompactSerialization();
    }

    public void assertBound(Response tokens, PublicJsonWebKey key, String subject)
            throws Exception {
        tokens.then().statusCode(200);
        assertEquals("DPoP", tokens.path("token_type"));
        String access = tokens.path("access_token");
        Response active = introspect(access);
        active.then().statusCode(200);
        assertEquals(true, active.path("active"));
        assertEquals("DPoP", active.path("token_type"));
        assertEquals(thumbprint(key), active.path("cnf.jkt"));
        String proof = proof(key, "GET", "/resource/guarded", access);
        Response resource = request()
                .header("Authorization", "DPoP " + access)
                .header("DPoP", proof)
                .get("/resource/guarded");
        resource.then().statusCode(200);
        assertEquals(subject, resource.path("subject"));
        request()
                .header("Authorization", "DPoP " + access)
                .header("DPoP", proof)
                .get("/resource/guarded")
                .then()
                .statusCode(401);
        request()
                .header("Authorization", "Bearer " + access)
                .get("/resource/guarded")
                .then()
                .statusCode(401);
    }

    public static String query(String location, String name) {
        return Arrays.stream(URI.create(location).getRawQuery().split("&"))
                .filter(p -> p.startsWith(name + "="))
                .map(p -> URLDecoder.decode(p.substring(name.length() + 1), StandardCharsets.UTF_8))
                .findFirst()
                .orElseThrow(() -> new AssertionError(location));
    }
}
