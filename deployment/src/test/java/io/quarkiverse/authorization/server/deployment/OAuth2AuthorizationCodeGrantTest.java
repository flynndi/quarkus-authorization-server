package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.PublicClientAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange.AuthorizationCodeExchange;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.AuthorizationCodeGrantHandler;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class OAuth2AuthorizationCodeGrantTest {

    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String PUBLIC_REDIRECT_URI = "https://client.example.com/public-callback";
    private static final String CONFIDENTIAL_REDIRECT_URI = "https://client.example.com/confidential-callback";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClass(ResourceOwnerAuthenticationMechanism.class)
                    .addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.http.root-path=/api
                                            quarkus.authorization-server.issuer=https://issuer.example.com/api
                                            quarkus.authorization-server.authorization-endpoint=/authorize
                                            quarkus.authorization-server.token-endpoint=/token
                                            quarkus.authorization-server.clients.public-client.client-authentication-methods=none
                                            quarkus.authorization-server.clients.public-client.authorization-grant-types=authorization_code,refresh_token
                                            quarkus.authorization-server.clients.public-client.redirect-uris=https://client.example.com/public-callback
                                            quarkus.authorization-server.clients.public-client.scopes=message.read,message.write
                                            quarkus.authorization-server.clients.attacker-client.client-authentication-methods=none
                                            quarkus.authorization-server.clients.attacker-client.authorization-grant-types=authorization_code
                                            quarkus.authorization-server.clients.attacker-client.redirect-uris=https://attacker.example.com/callback
                                            quarkus.authorization-server.clients.attacker-client.scopes=message.read
                                            quarkus.authorization-server.clients.confidential-client.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                            quarkus.authorization-server.clients.confidential-client.authorization-grant-types=authorization_code,refresh_token
                                            quarkus.authorization-server.clients.confidential-client.redirect-uris=https://client.example.com/confidential-callback
                                            quarkus.authorization-server.clients.confidential-client.scopes=message.read
                                            # Exercise an explicit opt-out; the default now requires PKCE.
                                            quarkus.authorization-server.clients.confidential-client.require-proof-key=false
                                            """),
                            "application.properties"));

    @Inject
    Instance<AuthorizationCodeGrantHandler> grantHandler;

    @Inject
    Instance<AuthorizationCodeExchange> grantProvider;

    @Inject
    Instance<PublicClientAuthenticationProvider> publicClientProvider;

    @Test
    void authorizationCodeBeansAreInstalledWithTheExtension() {
        assertTrue(this.grantHandler.isResolvable());
        assertTrue(this.grantProvider.isResolvable());
        assertTrue(this.publicClientProvider.isResolvable());
    }

    @Test
    void completesPublicClientAuthorizationCodePkceFlow() {
        String code = issuePublicCode("public-flow-user");

        publicTokenRequest("public-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("token_type", equalTo("Bearer"))
                .body("scope", equalTo("message.read"))
                .body("refresh_token", nullValue());
    }

    @Test
    void rejectsWrongVerifierWithoutConsumingCode() {
        String code = issuePublicCode("wrong-verifier-user");

        publicTokenRequest("public-client", code, "wrong-verifier", PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));

        publicTokenRequest("public-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(200);
    }

    @Test
    void rejectsRedirectUriMismatchWithoutConsumingCode() {
        String code = issuePublicCode("redirect-mismatch-user");

        publicTokenRequest("public-client", code, CODE_VERIFIER,
                "https://client.example.com/other-callback")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));

        publicTokenRequest("public-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(200);
    }

    @Test
    void invalidatesCodeUsedByAnotherClient() {
        String code = issuePublicCode("cross-client-user");

        publicTokenRequest("attacker-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));

        publicTokenRequest("public-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));
    }

    @Test
    void rejectsAuthorizationCodeReplay() {
        String code = issuePublicCode("replay-user");

        publicTokenRequest("public-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(200);
        publicTokenRequest("public-client", code, CODE_VERIFIER, PUBLIC_REDIRECT_URI)
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));
    }

    @Test
    void completesConfidentialClientFlowWithExplicitPkceOptOut() {
        Response authorizationResponse = given()
                .redirects().follow(false)
                .header("user", "confidential-flow-user")
                .queryParam("response_type", "code")
                .queryParam("client_id", "confidential-client")
                .queryParam("redirect_uri", CONFIDENTIAL_REDIRECT_URI)
                .queryParam("scope", "message.read")
                .queryParam("state", "confidential-state")
                .when().get("/authorize");
        String code = queryParameter(
                authorizationResponse.then().statusCode(302).extract().header("Location"), "code");

        String refreshToken = given()
                .auth().preemptive().basic("confidential-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", CONFIDENTIAL_REDIRECT_URI)
                .when().post("/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"))
                .body("refresh_token", notNullValue())
                .extract().path("refresh_token");

        given()
                .auth().preemptive().basic("confidential-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .when().post("/token")
                .then()
                .statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", equalTo(refreshToken));
    }

    @Test
    void validatesPkceWhenConfidentialClientProvidesChallenge() {
        Response authorizationResponse = given()
                .redirects().follow(false)
                .header("user", "confidential-pkce-user")
                .queryParam("response_type", "code")
                .queryParam("client_id", "confidential-client")
                .queryParam("redirect_uri", CONFIDENTIAL_REDIRECT_URI)
                .queryParam("scope", "message.read")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        String code = queryParameter(
                authorizationResponse.then().statusCode(302).extract().header("Location"), "code");

        confidentialTokenRequest(code, "wrong-verifier")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT));
        confidentialTokenRequest(code, CODE_VERIFIER)
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"));
    }

    private static String issuePublicCode(String principalName) {
        Response consentPage = given()
                .header("user", principalName)
                .queryParam("response_type", "code")
                .queryParam("client_id", "public-client")
                .queryParam("redirect_uri", PUBLIC_REDIRECT_URI)
                .queryParam("scope", "message.read")
                .queryParam("state", principalName + "-state")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        String internalState = hiddenState(
                consentPage.then().statusCode(200).contentType(ContentType.HTML).extract().asString());

        String location = given()
                .redirects().follow(false)
                .header("user", principalName)
                .contentType(ContentType.URLENC)
                .formParam("client_id", "public-client")
                .formParam("state", internalState)
                .formParam("scope", "message.read")
                .when().post("/authorize")
                .then()
                .statusCode(302)
                .extract().header("Location");
        return queryParameter(location, "code");
    }

    private static Response publicTokenRequest(String clientId, String code,
            String codeVerifier, String redirectUri) {
        return given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("client_id", clientId)
                .formParam("code", code)
                .formParam("redirect_uri", redirectUri)
                .formParam("code_verifier", codeVerifier)
                .when().post("/token");
    }

    private static Response confidentialTokenRequest(String code, String codeVerifier) {
        return given()
                .auth().preemptive().basic("confidential-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", CONFIDENTIAL_REDIRECT_URI)
                .formParam("code_verifier", codeVerifier)
                .when().post("/token");
    }

    private static String hiddenState(String consentPage) {
        Matcher matcher = Pattern.compile("name=\\\"state\\\" value=\\\"([^\\\"]+)\\\"").matcher(consentPage);
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    private static String queryParameter(String location, String name) {
        for (String parameter : URI.create(location).getRawQuery().split("&")) {
            String[] parts = parameter.split("=", 2);
            if (name.equals(URLDecoder.decode(parts[0], StandardCharsets.UTF_8))) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("Missing query parameter: " + name);
    }

    @ApplicationScoped
    public static class ResourceOwnerAuthenticationMechanism implements HttpAuthenticationMechanism {

        @Override
        public Uni<SecurityIdentity> authenticate(RoutingContext context,
                IdentityProviderManager identityProviderManager) {
            String principalName = context.request().getHeader("user");
            if (principalName == null) {
                return Uni.createFrom().nullItem();
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(principalName))
                    .build());
        }

        @Override
        public Uni<ChallengeData> getChallenge(RoutingContext context) {
            return Uni.createFrom().nullItem();
        }

        @Override
        public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
            return Collections.emptySet();
        }

        @Override
        public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
            return Uni.createFrom().nullItem();
        }
    }
}
