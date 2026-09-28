package io.quarkiverse.authorization.server.runtime.web.authentication;

import io.vertx.ext.web.RoutingContext;

/**
 * Converts an HTTP request into an authentication request.
 *
 * @param <T> converted authentication type
 */
public interface AuthenticationConverter<T> {

    /**
     * Returns an authentication request, or {@code null} when this converter does not support the request.
     */
    T convert(RoutingContext context);
}
