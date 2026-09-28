package io.quarkiverse.authorization.server.runtime.client.web;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

class ClientSecretBasicAuthenticationConverterTest {

    private final ClientSecretBasicAuthenticationConverter converter = new ClientSecretBasicAuthenticationConverter();

    @Test
    void extractsCredentialsWithoutReadingGrantParameters() {
        OAuth2ClientAuthenticationToken authentication = this.converter.convert(context());
        assertEquals("messaging-client", authentication.getPrincipal());
        assertEquals("secret", authentication.getCredentials());
        assertEquals(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                authentication.getClientAuthenticationMethod());
    }

    private static RoutingContext context() {
        String credentials = Base64.getEncoder().encodeToString(
                "messaging-client:secret".getBytes(StandardCharsets.UTF_8));
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                ClientSecretBasicAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("getHeader".equals(method.getName())) {
                        return "Basic " + credentials;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                ClientSecretBasicAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> {
                    if ("request".equals(method.getName())) {
                        return request;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
    }
}
