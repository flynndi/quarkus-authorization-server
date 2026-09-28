package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
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

class AuthorizationEndpointTest {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClass(ResourceOwnerAuthenticationMechanism.class)
                    .addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.http.root-path=/api
                                            quarkus.authorization-server.authorization-endpoint=/authorize
                                            quarkus.authorization-server.clients.messaging-client.client-secret=test-secret
                                            quarkus.authorization-server.clients.messaging-client.authorization-grant-types=authorization_code
                                            quarkus.authorization-server.clients.messaging-client.redirect-uris=https://client.example.com/callback
                                            quarkus.authorization-server.clients.messaging-client.scopes=message.read,message.write
                                            quarkus.authorization-server.clients.consent-client.client-authentication-methods=none
                                            quarkus.authorization-server.clients.consent-client.authorization-grant-types=authorization_code
                                            quarkus.authorization-server.clients.consent-client.redirect-uris=https://client.example.com/consent-callback
                                            quarkus.authorization-server.clients.consent-client.scopes=message.read,message.write
                                            quarkus.authorization-server.clients.deny-client.client-authentication-methods=none
                                            quarkus.authorization-server.clients.deny-client.authorization-grant-types=authorization_code
                                            quarkus.authorization-server.clients.deny-client.redirect-uris=https://client.example.com/deny-callback
                                            quarkus.authorization-server.clients.deny-client.scopes=message.read
                                            """),
                            "application.properties"));

    @Test
    void requiresAuthenticatedResourceOwner() {
        given()
                .queryParam("response_type", "code")
                .queryParam("client_id", "messaging-client")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize")
                .then().statusCode(401);
    }

    @Test
    void loginPagesAreNotInstalledByDefault() {
        given().basePath("").get("/login.html").then().statusCode(404);
        given().basePath("").get("/error.html").then().statusCode(404);
    }

    @Test
    void convertsGetAuthorizationRequestAtConfiguredPath() {
        given()
                .redirects().follow(false)
                .header("user", "resource-owner")
                .queryParam("response_type", "code")
                .queryParam("client_id", "messaging-client")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .queryParam("redirect_uri", "https://client.example.com/callback")
                .queryParam("scope", "message.read")
                .queryParam("state", "state")
                .when().get("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/callback?code="))
                .header("Location", containsString("&state=state"));
    }

    @Test
    void resolvesSingleRegisteredRedirectUriWhenRequestOmitsIt() {
        given()
                .redirects().follow(false)
                .header("user", "resource-owner")
                .queryParam("response_type", "code")
                .queryParam("client_id", "messaging-client")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .queryParam("scope", "message.read")
                .queryParam("state", "state")
                .when().get("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/callback?code="))
                .header("Location", containsString("&state=state"));
    }

    @Test
    void redirectsProtocolErrorOnlyAfterRedirectUriValidation() {
        given()
                .redirects().follow(false)
                .header("user", "resource-owner")
                .queryParam("response_type", "code")
                .queryParam("client_id", "messaging-client")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .queryParam("redirect_uri", "https://client.example.com/callback")
                .queryParam("scope", "message.unknown")
                .queryParam("state", "state")
                .when().get("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/callback?error=invalid_scope"))
                .header("Location", containsString("state=state"));

        given()
                .redirects().follow(false)
                .header("user", "resource-owner")
                .queryParam("response_type", "code")
                .queryParam("client_id", "messaging-client")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .queryParam("redirect_uri", "https://attacker.example.com/callback")
                .queryParam("scope", "message.read")
                .queryParam("state", "state")
                .when().get("/authorize")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .header("Location", equalTo(null))
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: redirect_uri"));
    }

    @Test
    void neverRedirectsUnknownClientError() {
        given()
                .redirects().follow(false)
                .header("user", "resource-owner")
                .queryParam("response_type", "code")
                .queryParam("client_id", "unknown-client")
                .queryParam("redirect_uri", "https://attacker.example.com/callback")
                .queryParam("state", "state")
                .when().get("/authorize")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .header("Location", equalTo(null))
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: client_id"));
    }

    @Test
    void requiresPkceForPublicAuthorizationCodeClient() {
        given()
                .redirects().follow(false)
                .header("user", "pkce-user")
                .queryParam("response_type", "code")
                .queryParam("client_id", "consent-client")
                .queryParam("redirect_uri", "https://client.example.com/consent-callback")
                .queryParam("scope", "message.read")
                .queryParam("state", "pkce-state")
                .when().get("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/consent-callback?error=invalid_request"))
                .header("Location", containsString(
                        "error_description=OAuth%202.0%20Parameter%3A%20code_challenge"))
                .header("Location", containsString("state=pkce-state"));
    }

    @Test
    void convertsPostAuthorizationConsent() {
        given()
                .header("user", "resource-owner")
                .contentType(ContentType.URLENC)
                .formParam("client_id", "messaging-client")
                .formParam("state", "state")
                .formParam("scope", "message.read", "message.write")
                .when().post("/authorize")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: state"));
    }

    @Test
    void displaysPersistsAndReusesAuthorizationConsent() {
        Response consentPage = given()
                .redirects().follow(false)
                .header("user", "consent-user")
                .queryParam("response_type", "code")
                .queryParam("client_id", "consent-client")
                .queryParam("redirect_uri", "https://client.example.com/consent-callback")
                .queryParam("scope", "message.read message.write")
                .queryParam("state", "client-state")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");

        consentPage.then().statusCode(200).contentType(ContentType.HTML);
        String internalState = hiddenState(consentPage.asString());
        assertNotEquals("client-state", internalState);

        given()
                .redirects().follow(false)
                .header("user", "consent-user")
                .contentType(ContentType.URLENC)
                .formParam("client_id", "consent-client")
                .formParam("state", internalState)
                .formParam("scope", "message.read", "message.write")
                .when().post("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/consent-callback?code="))
                .header("Location", containsString("&state=client-state"));

        given()
                .redirects().follow(false)
                .header("user", "consent-user")
                .queryParam("response_type", "code")
                .queryParam("client_id", "consent-client")
                .queryParam("redirect_uri", "https://client.example.com/consent-callback")
                .queryParam("scope", "message.read message.write")
                .queryParam("state", "second-client-state")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/consent-callback?code="))
                .header("Location", containsString("&state=second-client-state"));
    }

    @Test
    void redirectsDeniedConsentAndConsumesInFlightAuthorization() {
        Response consentPage = given()
                .header("user", "deny-user")
                .queryParam("response_type", "code")
                .queryParam("client_id", "deny-client")
                .queryParam("redirect_uri", "https://client.example.com/deny-callback")
                .queryParam("scope", "message.read")
                .queryParam("state", "deny-client-state")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        String internalState = hiddenState(consentPage.then().statusCode(200).extract().asString());

        given()
                .redirects().follow(false)
                .header("user", "deny-user")
                .contentType(ContentType.URLENC)
                .formParam("client_id", "deny-client")
                .formParam("state", internalState)
                .when().post("/authorize")
                .then()
                .statusCode(302)
                .header("Location", containsString(
                        "https://client.example.com/deny-callback?error=access_denied"))
                .header("Location", containsString("state=deny-client-state"));

        given()
                .header("user", "deny-user")
                .contentType(ContentType.URLENC)
                .formParam("client_id", "deny-client")
                .formParam("state", internalState)
                .when().post("/authorize")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    @Test
    void returnsOAuthErrorWithoutRedirectingToUnvalidatedUri() {
        given()
                .redirects().follow(false)
                .header("user", "resource-owner")
                .queryParam("response_type", "token")
                .queryParam("client_id", "messaging-client")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                .queryParam("redirect_uri", "https://attacker.example.com/callback")
                .queryParam("state", "state")
                .when().get("/authorize")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .header("Location", equalTo(null))
                .body("error", equalTo(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE))
                .body("error_description", equalTo("OAuth 2.0 Parameter: response_type"))
                .body("error_uri", equalTo(ERROR_URI));
    }

    @Test
    void rejectsNonFormPostAndDoesNotInstallOtherMethodsOrDefaultPath() {
        given()
                .header("user", "resource-owner")
                .contentType(ContentType.JSON)
                .body("{}")
                .when().post("/authorize")
                .then().statusCode(415);

        given().header("user", "resource-owner").when().put("/authorize").then().statusCode(403);
        given().header("user", "resource-owner").when().get("/oauth2/authorize").then().statusCode(404);
    }

    private static String hiddenState(String consentPage) {
        Matcher matcher = Pattern.compile("name=\\\"state\\\" value=\\\"([^\\\"]+)\\\"").matcher(consentPage);
        assertTrue(matcher.find());
        return matcher.group(1);
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
