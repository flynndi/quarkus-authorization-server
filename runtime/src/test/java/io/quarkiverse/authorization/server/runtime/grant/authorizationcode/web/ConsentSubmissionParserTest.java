package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.authorizationcode.ConsentSubmission;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

class ConsentSubmissionParserTest {

    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();

    private final ConsentSubmissionParser converter = new ConsentSubmissionParser();

    @Test
    void convertsAuthorizationConsent() {
        MultiMap parameters = validParameters()
                .add("scope", "message.read")
                .add("scope", "message.write")
                .add("action", "approve")
                .add("resource", "one")
                .add("resource", "two");
        RoutingContext context = AuthorizationRequestParserTest.context(
                HttpMethod.POST, parameters, new QuarkusHttpUser(PRINCIPAL));

        ConsentSubmission authentication = this.converter.parse(context);

        assertEquals(
                "https://issuer.example.com/oauth2/authorize",
                authentication.getAuthorizationUri());
        assertEquals("messaging-client", authentication.getClientId());
        assertEquals(PRINCIPAL, authentication.getPrincipal());
        assertEquals("state", authentication.getState());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals("approve", authentication.getAdditionalParameters().get("action"));
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) authentication.getAdditionalParameters().get("resource"));
    }

    @Test
    void recognizesExplicitDenialAndRejectsAmbiguousOrUnknownDecisions() {
        ConsentSubmission submission = this.converter.parse(AuthorizationRequestParserTest.context(HttpMethod.POST,
                ConsentSubmissionParserTest.validParameters().add("consent_action", "deny"), new QuarkusHttpUser(PRINCIPAL)));
        assertEquals(true, submission.isDenied());
        this.assertInvalidParameter(ConsentSubmissionParserTest.validParameters().add("consent_action", "deny")
                .add("consent_action", "approve"), "consent_action");
        this.assertInvalidParameter(ConsentSubmissionParserTest.validParameters().add("consent_action", ""), "consent_action");
        this.assertInvalidParameter(ConsentSubmissionParserTest.validParameters().add("consent_action", "cancel"),
                "consent_action");
    }

    @Test
    void onlyConvertsPostConsentRequests() {
        assertNull(
                this.converter.parse(
                        AuthorizationRequestParserTest.context(
                                HttpMethod.GET,
                                validParameters(),
                                new QuarkusHttpUser(PRINCIPAL))));
        assertNull(
                this.converter.parse(
                        AuthorizationRequestParserTest.context(
                                HttpMethod.POST,
                                validParameters().add("response_type", "code"),
                                new QuarkusHttpUser(PRINCIPAL))));
    }

    @Test
    void rejectsInvalidClientIdAndState() {
        assertInvalidParameter(validParameters().remove("client_id"), "client_id");
        assertInvalidParameter(validParameters().add("client_id", "other-client"), "client_id");
        assertInvalidParameter(validParameters().remove("state"), "state");
        assertInvalidParameter(validParameters().add("state", "other-state"), "state");
    }

    private void assertInvalidParameter(MultiMap parameters, String parameterName) {
        AuthorizationRequestException exception = assertThrows(
                AuthorizationRequestException.class,
                () -> this.converter.parse(
                        AuthorizationRequestParserTest.context(
                                HttpMethod.POST,
                                parameters,
                                new QuarkusHttpUser(PRINCIPAL))));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Parameter: " + parameterName, exception.getError().getDescription());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("client_id", "messaging-client")
                .add("state", "state");
    }
}
