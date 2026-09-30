package io.quarkiverse.authorization.server.runtime.web;

import java.util.concurrent.Callable;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.VertxContextSupport;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Worker/request-scope boundary for synchronous protocol operations, including CDI HTTP context
 * access.
 */
@Singleton
public final class ProtocolExecutor {
    private final CurrentVertxRequest currentRequest;

    @Inject
    public ProtocolExecutor(CurrentVertxRequest currentRequest) {
        this.currentRequest = currentRequest;
    }

    public <T> Uni<T> execute(AuthenticationRequest request, Callable<T> operation) {
        RoutingContext context = HttpSecurityUtils.getRoutingContextAttribute(request);
        // Programmatic authentication may have no HTTP request. Preserve any caller-owned binding.
        return context == null ? VertxContextSupport.executeBlocking(operation) : this.execute(context, operation);
    }

    public <T> Uni<T> execute(RoutingContext context, Callable<T> operation) {
        return VertxContextSupport.executeBlocking(
                () -> {
                    RoutingContext previous = this.currentRequest.getCurrent();
                    this.currentRequest.setCurrent(context);
                    try {
                        return operation.call();
                    } finally {
                        // Restore caller-owned state when blocking work exits, including after
                        // cancellation. VertxContextSupport owns scope activation and release.
                        this.currentRequest.setCurrent(previous);
                    }
                });
    }
}
