package io.quarkiverse.authorization.server.grant.authorizationcode;

import java.util.Set;

import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;

/** Renders the Authorization Endpoint response when resource-owner consent is required. */
public interface OAuth2AuthorizationConsentPage {

    void displayConsent(
            RoutingContext context,
            String clientId,
            SecurityIdentity principal,
            Set<String> requestedScopes,
            Set<String> authorizedScopes,
            String state);
}
