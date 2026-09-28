package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

class DefaultDeviceVerificationPageTest {

    private final DefaultDeviceVerificationPage page = new DefaultDeviceVerificationPage();

    @Test
    void rendersVerificationFormWithoutCookieTokenAndWithSecurityHeaders() throws NoSuchAlgorithmException {
        ResponseCapture capture = new ResponseCapture();
        this.page.displayVerification(context(capture));

        assertTrue(capture.body.contains("name=\"user_code\""));
        assertFalse(capture.body.contains("csrf_token"));
        assertTrue(
                capture.headers.get(HttpHeaders.CONTENT_TYPE.toString()).startsWith("text/html"));
        assertTrue(capture.headers.get(HttpHeaders.CACHE_CONTROL.toString()).contains("no-store"));
        String stylesheet = capture.body.substring(capture.body.indexOf("<style>") + 7, capture.body.indexOf("</style>"));
        String hash = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(stylesheet.getBytes(StandardCharsets.UTF_8)));
        String policy = capture.headers.get("Content-Security-Policy");
        assertTrue(policy.contains("style-src 'sha256-" + hash + "'"));
        assertTrue(policy.contains("default-src 'none'"));
        assertTrue(policy.contains("form-action 'self'"));
        assertFalse(policy.contains("'unsafe-inline'"));
        assertEquals("nosniff", capture.headers.get("X-Content-Type-Options"));
    }

    @Test
    void rendersConsentAndEscapesAllDynamicValues() {
        ResponseCapture capture = new ResponseCapture();
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("owner<script>"))
                .build();

        this.page.displayConfirmation(
                context(capture),
                "client<&>",
                principal,
                Set.of("message.read", "message.write<script>"),
                Set.of("message.read"),
                "BCDF-GHJK",
                "state<&>");

        assertTrue(capture.body.contains("client&lt;&amp;&gt;"));
        assertTrue(capture.body.contains("owner&lt;script&gt;"));
        assertTrue(capture.body.contains("message.write&lt;script&gt;"));
        assertFalse(capture.body.contains("<script>"));
        assertTrue(capture.body.contains("name=\"user_code\" value=\"BCDF-GHJK\""));
        assertTrue(capture.body.contains("name=\"state\" value=\"state&lt;&amp;&gt;\""));
        assertTrue(capture.body.contains("name=\"approved\" value=\"true\""));
        assertTrue(capture.body.contains("name=\"approved\" value=\"false\""));
        assertTrue(capture.body.contains("id=\"device-user-code\">BCDF-GHJK</strong>"));
        assertFalse(capture.body.contains("csrf_token"));
        assertTrue(capture.body.contains("Permissions for this device:"));
        String denialForm = capture.body.substring(capture.body.lastIndexOf("<form"));
        assertTrue(capture.body.contains("id=\"cancel-consent\" form=\"device-denial\""));
        assertTrue(denialForm.contains("id=\"device-denial\""));
        assertFalse(denialForm.contains("name=\"scope\""));
    }

    @Test
    void rendersSuccessAndBoundedErrorMessages() {
        ResponseCapture success = new ResponseCapture();
        this.page.displaySuccess(context(success), "client<script>");
        assertTrue(success.body.contains("Device authorized"));
        assertTrue(success.body.contains("client&lt;script&gt;"));

        ResponseCapture error = new ResponseCapture();
        this.page.displayError(
                context(error),
                new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_GRANT,
                        "<script>alert(1)</script>",
                        "https://attacker.example"));
        assertTrue(error.body.contains("invalid_grant"));
        assertTrue(error.body.contains("invalid, expired, or has already been used"));
        assertFalse(error.body.contains("alert(1)"));
    }

    private static RoutingContext context(ResponseCapture capture) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                DefaultDeviceVerificationPageTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("path".equals(method.getName())) {
                        return "/oauth2/device_verification";
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        HttpServerResponse response = (HttpServerResponse) Proxy.newProxyInstance(
                DefaultDeviceVerificationPageTest.class.getClassLoader(),
                new Class<?>[] { HttpServerResponse.class },
                (proxy, method, arguments) -> {
                    switch (method.getName()) {
                        case "putHeader" -> capture.headers.put(arguments[0].toString(), arguments[1].toString());
                        case "end" -> {
                            capture.body = arguments[0].toString();
                            return null;
                        }
                        default -> throw new UnsupportedOperationException(method.toString());
                    }
                    return proxy;
                });
        return (RoutingContext) Proxy.newProxyInstance(
                DefaultDeviceVerificationPageTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "request" -> request;
                    case "response" -> response;
                    default -> throw new UnsupportedOperationException(method.toString());
                });
    }

    private static final class ResponseCapture {

        private final Map<String, String> headers = new LinkedHashMap<>();
        private String body;
    }
}
