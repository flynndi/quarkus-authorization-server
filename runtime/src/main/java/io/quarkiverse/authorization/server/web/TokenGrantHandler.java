package io.quarkiverse.authorization.server.web;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/** HTTP adapter for one token grant. The adapter owns parsing and typed service invocation. */
public interface TokenGrantHandler {
    /** Called outside a request during installation; duplicate grant types fail startup. */
    AuthorizationGrantType getGrantType();

    /** Defers protocol work until subscription; implementations own their execution boundary. */
    Uni<TokenIssuanceResult> handle(RoutingContext context);
}
