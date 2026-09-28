package io.quarkiverse.authorization.server.runtime.context;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.smallrye.common.vertx.ContextLocals;
import io.smallrye.common.vertx.VertxContext;
import io.vertx.core.Vertx;

/** Uses the HTTP request's duplicated Vert.x context, which Quarkus also preserves for blocking authentication. */
@Singleton
public final class CurrentAuthorizationServerContext implements AuthorizationServerContext {

    public static final String ATTRIBUTE = CurrentAuthorizationServerContext.class.getName();

    private final AuthorizationServerSettings defaults;

    @Inject
    public CurrentAuthorizationServerContext(AuthorizationServerSettings defaults) {
        this.defaults = defaults;
    }

    @Override
    public boolean isMultipleIssuersAllowed() {
        return this.defaults.isMultipleIssuersAllowed();
    }

    @Override
    public String getIssuer() {
        return this.getAuthorizationServerSettings().getIssuer();
    }

    @Override
    public AuthorizationServerSettings getAuthorizationServerSettings() {
        if (!this.defaults.isMultipleIssuersAllowed()) {
            return this.defaults;
        }
        var context = Vertx.currentContext();
        AuthorizationServerSettings current = context != null && VertxContext.isDuplicatedContext(context)
                ? ContextLocals.get(ATTRIBUTE, null)
                : null;
        if (current == null) {
            throw new IllegalStateException("No authorization-server issuer is selected for this request");
        }
        return current;
    }
}
