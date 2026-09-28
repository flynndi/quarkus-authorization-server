package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.util.Set;
import java.util.TreeSet;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.ConsentSubmission;
import io.quarkiverse.authorization.server.grant.authorizationcode.OAuth2AuthorizationConsentPage;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.runtime.web.DefaultBrowserPage;
import io.quarkus.arc.DefaultBean;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;

/**
 * Default consent page used when the application does not provide its own HTTP response
 * implementation.
 */
@Singleton
@DefaultBean
public final class DefaultConsentPage implements OAuth2AuthorizationConsentPage {

    @Override
    public void displayConsent(
            RoutingContext context,
            String clientId,
            SecurityIdentity principal,
            Set<String> requestedScopes,
            Set<String> authorizedScopes,
            String state) {
        Set<String> scopesToAuthorize = new TreeSet<>(requestedScopes);
        scopesToAuthorize.remove(OidcScopes.OPENID);
        scopesToAuthorize.removeAll(authorizedScopes);
        Set<String> previouslyAuthorizedScopes = new TreeSet<>(requestedScopes);
        previouslyAuthorizedScopes.retainAll(authorizedScopes);
        previouslyAuthorizedScopes.remove(OidcScopes.OPENID);

        StringBuilder page = new StringBuilder(2048);
        page.append("<p class=\"lead\">Review this application's access to your account.</p>")
                .append("<dl class=\"details\"><div><dt>Application</dt><dd>")
                .append(DefaultBrowserPage.escapeHtml(clientId))
                .append("</dd></div><div><dt>Signed in as</dt><dd>")
                .append(DefaultBrowserPage.escapeHtml(principal.getPrincipal().getName()))
                .append("</dd></div></dl><form name=\"consent_form\" method=\"post\" action=\"")
                .append(DefaultBrowserPage.escapeHtml(context.request().path()))
                .append("\"><input type=\"hidden\" name=\"")
                .append(OAuth2ParameterNames.CLIENT_ID)
                .append("\" value=\"")
                .append(DefaultBrowserPage.escapeHtml(clientId))
                .append("\"><input type=\"hidden\" name=\"")
                .append(OAuth2ParameterNames.STATE)
                .append("\" value=\"")
                .append(DefaultBrowserPage.escapeHtml(state))
                .append("\">");

        if (!scopesToAuthorize.isEmpty()) {
            page.append("<fieldset><legend>Requested permissions</legend>");
        }
        for (String scope : scopesToAuthorize) {
            page.append("<label class=\"scope\"><input type=\"checkbox\" name=\"")
                    .append(OAuth2ParameterNames.SCOPE)
                    .append("\" value=\"")
                    .append(DefaultBrowserPage.escapeHtml(scope))
                    .append("\"><span>")
                    .append(DefaultBrowserPage.escapeHtml(scope))
                    .append("</span></label>");
        }
        if (!scopesToAuthorize.isEmpty()) {
            page.append("</fieldset>");
        }
        if (!previouslyAuthorizedScopes.isEmpty()) {
            page.append("<fieldset><legend>Previously authorized:</legend>");
            for (String scope : previouslyAuthorizedScopes) {
                page.append("<label class=\"scope granted\"><input type=\"checkbox\" checked disabled><span>")
                        .append(DefaultBrowserPage.escapeHtml(scope))
                        .append("</span></label>");
            }
            page.append("</fieldset>");
        }
        page.append("<div class=\"actions\"><button type=\"submit\" id=\"submit-consent\" name=\"")
                .append(ConsentSubmission.ACTION_PARAMETER)
                .append("\" value=\"").append(ConsentSubmission.APPROVE_ACTION)
                .append("\">Approve</button>")
                .append("<button type=\"submit\" class=\"secondary\" id=\"cancel-consent\" name=\"")
                .append(ConsentSubmission.ACTION_PARAMETER)
                .append("\" value=\"").append(ConsentSubmission.DENY_ACTION)
                .append("\">Deny</button>")
                .append("</div></form>");

        DefaultBrowserPage.write(context, "Consent required", page.toString());
    }
}
