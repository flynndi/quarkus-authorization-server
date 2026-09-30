package io.quarkiverse.authorization.server.deployment;

import java.lang.reflect.Proxy;
import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

/** Minimal HTTP input for subscription/cancellation tests running on explicit Vert.x contexts. */
final class TokenGrantHttpFixture {
    static RoutingContext context(Map<String, String> parameters, SecurityIdentity identity) {
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        MultiMap headers = MultiMap.caseInsensitiveMultiMap();
        parameters.forEach(form::add);
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                HttpServerRequest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "formAttributes" -> form;
                    case "headers" -> headers;
                    case "getHeader" -> headers.get((String) args[0]);
                    case "toString" -> "TokenGrantHttpFixture request";
                    default ->
                        throw new UnsupportedOperationException(
                                method.getName());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                RoutingContext.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "request" -> request;
                    case "user" -> new QuarkusHttpUser(identity);
                    case "toString" -> "TokenGrantHttpFixture context";
                    default ->
                        throw new UnsupportedOperationException(
                                method.getName());
                });
    }
}
