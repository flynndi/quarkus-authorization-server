package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentSubmission;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationRequest;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

class DeviceVerificationRequestParserTest {

    private static final SecurityIdentity PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("resource-owner"))
            .build();
    private final DeviceVerificationRequestParser verificationConverter = new DeviceVerificationRequestParser();
    private final DeviceConsentSubmissionParser consentConverter = new DeviceConsentSubmissionParser();

    @Test
    void convertsAndNormalizesGetAndPostUserCode() {
        MultiMap get = MultiMap.caseInsensitiveMultiMap()
                .add("user_code", "bcdf ghjk")
                .add("custom", "one")
                .add("custom", "two");
        DeviceVerificationRequest getResult = this.verificationConverter.parse(
                context(
                        HttpMethod.GET,
                        get,
                        MultiMap.caseInsensitiveMultiMap(),
                        PRINCIPAL));
        assertEquals("BCDF-GHJK", getResult.getUserCode());
        assertSame(PRINCIPAL, getResult.getPrincipal());
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) getResult.getAdditionalParameters().get("custom"));

        MultiMap post = MultiMap.caseInsensitiveMultiMap().add("user_code", "bcdf-ghjk");
        DeviceVerificationRequest postResult = this.verificationConverter.parse(
                context(
                        HttpMethod.POST,
                        MultiMap.caseInsensitiveMultiMap(),
                        post,
                        PRINCIPAL));
        assertEquals("BCDF-GHJK", postResult.getUserCode());
        assertTrue(postResult.getAdditionalParameters().isEmpty());
    }

    @Test
    void onlyConvertsVerificationRequestsAndRejectsInvalidUserCode() {
        assertNull(
                this.verificationConverter.parse(
                        context(
                                HttpMethod.GET,
                                MultiMap.caseInsensitiveMultiMap(),
                                MultiMap.caseInsensitiveMultiMap(),
                                PRINCIPAL)));
        assertNull(
                this.verificationConverter.parse(
                        context(
                                HttpMethod.GET,
                                MultiMap.caseInsensitiveMultiMap()
                                        .add("user_code", "BCDF-GHJK")
                                        .add("state", "state"),
                                MultiMap.caseInsensitiveMultiMap(),
                                PRINCIPAL)));
        assertNull(
                this.verificationConverter.parse(
                        context(
                                HttpMethod.PUT,
                                MultiMap.caseInsensitiveMultiMap().add("user_code", "BCDF-GHJK"),
                                MultiMap.caseInsensitiveMultiMap(),
                                PRINCIPAL)));

        assertInvalidUserCode(MultiMap.caseInsensitiveMultiMap().add("user_code", "short"));
        assertInvalidUserCode(
                MultiMap.caseInsensitiveMultiMap()
                        .add("user_code", "BCDF-GHJK")
                        .add("user_code", "NPQR-STVW"));
    }

    @Test
    void convertsConfirmationAndExcludesApprovalParameter() {
        MultiMap form = MultiMap.caseInsensitiveMultiMap()
                .add("client_id", "device-client")
                .add("user_code", "bcdf ghjk")
                .add("state", "state")
                .add("scope", "message.read")
                .add("scope", "message.write")
                .add(OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME, "true")
                .add("custom", "value");

        DeviceConsentSubmission result = this.consentConverter.parse(
                context(
                        HttpMethod.POST,
                        MultiMap.caseInsensitiveMultiMap(),
                        form,
                        PRINCIPAL));

        assertEquals("device-client", result.getClientId());
        assertEquals("BCDF-GHJK", result.getUserCode());
        assertEquals("state", result.getState());
        assertTrue(result.isApproved());
        assertEquals(Set.of("message.read", "message.write"), result.getScopes());
        assertEquals("value", result.getAdditionalParameters().get("custom"));
        assertFalse(
                result.getAdditionalParameters()
                        .containsKey(OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME));
    }

    @Test
    void rejectsInvalidConsentBindingParameters() {
        MultiMap valid = consentParameters();
        assertInvalidConsent(copy(valid).remove("client_id"), "client_id");
        assertInvalidConsent(copy(valid).add("client_id", "other"), "client_id");
        assertInvalidConsent(copy(valid).remove("user_code"), "user_code");
        assertInvalidConsent(copy(valid).add("user_code", "NPQR-STVW"), "user_code");
        assertInvalidConsent(copy(valid).remove("state"), "state");
        assertInvalidConsent(copy(valid).add("state", "other"), "state");
        assertInvalidConsent(copy(valid).remove("approved"), "approved");
        assertInvalidConsent(copy(valid).set("approved", "yes"), "approved");
        assertInvalidConsent(copy(valid).add("approved", "false"), "approved");
        assertInvalidConsent(copy(valid).set("approved", ""), "approved");
    }

    @Test
    void denialIsExplicitAndMissingStateCannotFallBackToUserCodeVerification() {
        MultiMap form = consentParameters().set("approved", "false");
        assertFalse(
                this.consentConverter
                        .parse(
                                context(
                                        HttpMethod.POST,
                                        MultiMap.caseInsensitiveMultiMap(),
                                        form,
                                        PRINCIPAL))
                        .isApproved());
        form.remove("state");
        assertNull(
                this.verificationConverter.parse(
                        context(
                                HttpMethod.POST,
                                MultiMap.caseInsensitiveMultiMap(),
                                form,
                                PRINCIPAL)));
        assertInvalidConsent(form, "state");
    }

    private void assertInvalidUserCode(MultiMap query) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.verificationConverter.parse(
                        context(
                                HttpMethod.GET,
                                query,
                                MultiMap.caseInsensitiveMultiMap(),
                                PRINCIPAL)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: user_code", exception.getError().getDescription());
    }

    private void assertInvalidConsent(MultiMap form, String parameterName) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.consentConverter.parse(
                        context(
                                HttpMethod.POST,
                                MultiMap.caseInsensitiveMultiMap(),
                                form,
                                PRINCIPAL)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Parameter: " + parameterName, exception.getError().getDescription());
    }

    private static MultiMap consentParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("client_id", "device-client")
                .add("user_code", "BCDF-GHJK")
                .add("state", "state")
                .add("approved", "true");
    }

    private static MultiMap copy(MultiMap parameters) {
        return MultiMap.caseInsensitiveMultiMap().addAll(parameters);
    }

    private static RoutingContext context(
            HttpMethod method, MultiMap query, MultiMap form, SecurityIdentity principal) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                DeviceVerificationRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, invokedMethod, arguments) -> switch (invokedMethod.getName()) {
                    case "method" -> method;
                    case "formAttributes" -> form;
                    case "absoluteURI" ->
                        "https://issuer.example/api/device/activate?ignored=true";
                    default ->
                        throw new UnsupportedOperationException(
                                invokedMethod.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                DeviceVerificationRequestParserTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, invokedMethod, arguments) -> switch (invokedMethod.getName()) {
                    case "request" -> request;
                    case "queryParams" -> query;
                    case "user" ->
                        principal != null
                                ? new QuarkusHttpUser(principal)
                                : null;
                    default ->
                        throw new UnsupportedOperationException(
                                invokedMethod.toString());
                });
    }
}
