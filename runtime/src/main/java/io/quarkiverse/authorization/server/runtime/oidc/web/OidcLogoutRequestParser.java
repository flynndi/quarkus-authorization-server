package io.quarkiverse.authorization.server.runtime.oidc.web;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutRequest;
import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Parses logout parameters from GET queries or POST forms and requires id_token_hint. */
public final class OidcLogoutRequestParser {
    private final OidcSessionManager sessionManager;

    public OidcLogoutRequestParser(OidcSessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public OidcLogoutRequest parse(RoutingContext context) {
        MultiMap parameters = context.request().method() == HttpMethod.GET
                ? context.queryParams()
                : context.request().formAttributes();
        String hint = parameter(parameters, "id_token_hint", true);
        String clientId = parameter(parameters, OAuth2ParameterNames.CLIENT_ID, false);
        String redirectUri = parameter(parameters, "post_logout_redirect_uri", false);
        String state = parameter(parameters, OAuth2ParameterNames.STATE, false);
        SecurityIdentity principal = context.user() instanceof QuarkusHttpUser user
                ? user.getSecurityIdentity()
                : QuarkusSecurityIdentity.builder().setAnonymous(true).build();
        SessionInformation session = this.sessionManager != null && !principal.isAnonymous()
                ? this.sessionManager.getSessionInformation(context, principal)
                : null;
        return new OidcLogoutRequest(
                hint,
                principal,
                session != null ? session.sessionId() : null,
                clientId,
                redirectUri,
                state);
    }

    private static String parameter(MultiMap parameters, String name, boolean required) {
        String value = parameters.get(name);
        if (parameters.getAll(name).size() > 1 || required && (value == null || value.isBlank())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "OpenID Connect 1.0 Logout Request Parameter: " + name,
                            null));
        }
        return value;
    }
}
