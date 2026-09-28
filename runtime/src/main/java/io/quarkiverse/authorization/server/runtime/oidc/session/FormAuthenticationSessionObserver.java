package io.quarkiverse.authorization.server.runtime.oidc.session;

import java.util.Map;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent;
import io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/** Captures only successful fresh Form logins, after every identity augmentor has completed. */
@Singleton
public final class FormAuthenticationSessionObserver implements SecurityIdentityAugmentor {
    private final OidcSessionManager sessionManager;

    @Inject
    public FormAuthenticationSessionObserver(OidcSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        return Uni.createFrom().item(identity);
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context,
            Map<String, Object> attributes) {
        RoutingContext routingContext = HttpSecurityUtils.getRoutingContextAttribute(attributes);
        // Quarkus emits FormAuthenticationEvent before its mechanism attaches RoutingContext to the identity.
        if (routingContext != null && !identity.isAnonymous()
                && routingContext.get(HttpAuthenticationMechanism.class.getName()) instanceof FormAuthenticationMechanism) {
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder(identity)
                    .addAttribute(HttpSecurityUtils.ROUTING_CONTEXT_ATTRIBUTE, routingContext).build());
        }
        return Uni.createFrom().item(identity);
    }

    void onLogin(@Observes FormAuthenticationEvent event) {
        if (this.sessionManager instanceof FormAuthenticationSessionManager formSessionManager) {
            SecurityIdentity principal = event.getSecurityIdentity();
            RoutingContext context = HttpSecurityUtils.getRoutingContextAttribute(principal);
            if (context != null && !principal.isAnonymous()) {
                formSessionManager.login(context, principal);
            }
        }
    }
}
