package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

class DefaultConsentPageTest {

    @Test
    void rendersOnlyNewScopesAsSelectableAndEscapesDynamicValues() {
        ResponseCapture capture = new ResponseCapture();
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner<script>"))
                .build();

        new DefaultConsentPage()
                .displayConsent(
                        context(capture),
                        "client<&>",
                        principal,
                        Set.of("message.read", "message.write"),
                        Set.of("message.read"),
                        "internal-state");

        assertTrue(capture.body.contains("name=\"scope\" value=\"message.write\""));
        assertFalse(capture.body.contains("name=\"scope\" value=\"message.read\""));
        assertTrue(capture.body.contains("Previously authorized:"));
        assertTrue(capture.body.contains("client&lt;&amp;&gt;"));
        assertTrue(capture.body.contains("resource-owner&lt;script&gt;"));
        assertTrue(capture.body.contains("name=\"state\" value=\"internal-state\""));
        assertTrue(capture.body.contains("name=\"consent_action\" value=\"deny\""));
        assertFalse(capture.body.contains("<script>"));
        assertTrue(capture.headers.get(HttpHeaders.CACHE_CONTROL.toString()).equals("no-store"));
        assertTrue(
                capture.headers.get(HttpHeaders.CONTENT_TYPE.toString()).startsWith("text/html"));
    }

    private static RoutingContext context(ResponseCapture capture) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                DefaultConsentPageTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("path".equals(method.getName())) {
                        return "/oauth2/authorize";
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        HttpServerResponse response = (HttpServerResponse) Proxy.newProxyInstance(
                DefaultConsentPageTest.class.getClassLoader(),
                new Class<?>[] { HttpServerResponse.class },
                (proxy, method, arguments) -> {
                    switch (method.getName()) {
                        case "putHeader" ->
                            capture.headers.put(
                                    arguments[0].toString(),
                                    arguments[1].toString());
                        case "end" -> {
                            capture.body = arguments[0].toString();
                            return null;
                        }
                        default ->
                            throw new UnsupportedOperationException(
                                    method.toString());
                    }
                    return proxy;
                });
        return (RoutingContext) Proxy.newProxyInstance(
                DefaultConsentPageTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "request" -> request;
                    case "response" -> response;
                    default ->
                        throw new UnsupportedOperationException(
                                method.toString());
                });
    }

    private static final class ResponseCapture {

        private final Map<String, String> headers = new LinkedHashMap<>();
        private String body;
    }
}
