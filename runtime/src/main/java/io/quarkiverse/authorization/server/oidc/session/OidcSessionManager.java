package io.quarkiverse.authorization.server.oidc.session;

import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;

/**
 * Adapts the consuming application's session lifecycle to OIDC. It does not authenticate a user.
 * Applications using a session mechanism other than Quarkus Form Authentication can provide this CDI bean.
 * Session lookup runs at the HTTP boundary and must not block; return verified session metadata already
 * associated with the current identity/request, never data supplied in OAuth request parameters.
 */
public interface OidcSessionManager {
    SessionInformation getSessionInformation(RoutingContext context, SecurityIdentity principal);

    void logout(RoutingContext context, SecurityIdentity principal);
}
