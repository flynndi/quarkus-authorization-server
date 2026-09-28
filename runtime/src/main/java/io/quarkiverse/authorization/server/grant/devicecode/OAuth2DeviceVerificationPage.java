package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Set;

import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;

/**
 * Renders the browser-facing Device Verification Endpoint responses.
 */
public interface OAuth2DeviceVerificationPage {

    String APPROVAL_PARAMETER_NAME = "approved";

    void displayVerification(RoutingContext context);

    /**
     * Display the code for verification and submit state plus approved=true/false explicitly.
     * authorizedScopes need no further scope selection; they do not bypass device confirmation.
     */
    void displayConfirmation(
            RoutingContext context,
            String clientId,
            SecurityIdentity principal,
            Set<String> requestedScopes,
            Set<String> authorizedScopes,
            String userCode,
            String state);

    void displaySuccess(RoutingContext context, String clientId);

    void displayError(RoutingContext context, OAuth2Error error);
}
