package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import java.util.Set;
import java.util.TreeSet;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.runtime.web.DefaultBrowserPage;
import io.quarkus.arc.DefaultBean;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;

/**
 * Default browser pages used when the application does not provide its own Device Verification responses.
 */
@Singleton
@DefaultBean
public final class DefaultDeviceVerificationPage implements OAuth2DeviceVerificationPage {

    @Override
    public void displayVerification(RoutingContext context) {
        StringBuilder page = new StringBuilder(512)
                .append("<p class=\"lead\">Enter the activation code displayed on your device.</p>")
                .append("<form method=\"post\" action=\"")
                .append(DefaultBrowserPage.escapeHtml(context.request().path()))
                .append("\">")
                .append("<div class=\"field\"><label for=\"user_code\">Activation code</label>")
                .append("<input id=\"user_code\" type=\"text\" name=\"")
                .append(OAuth2ParameterNames.USER_CODE)
                .append("\" autocomplete=\"one-time-code\" autocapitalize=\"characters\" spellcheck=\"false\" required autofocus></div>")
                .append("<button type=\"submit\" id=\"submit-user-code\">Continue</button>")
                .append("</form>");
        DefaultBrowserPage.writeLocalForm(context, "Device verification", page.toString());
    }

    @Override
    public void displayConfirmation(
            RoutingContext context,
            String clientId,
            SecurityIdentity principal,
            Set<String> requestedScopes,
            Set<String> authorizedScopes,
            String userCode,
            String state) {
        Set<String> scopesToAuthorize = new TreeSet<>(requestedScopes);
        scopesToAuthorize.removeAll(authorizedScopes);
        Set<String> previouslyAuthorizedScopes = new TreeSet<>(requestedScopes);
        previouslyAuthorizedScopes.retainAll(authorizedScopes);

        StringBuilder page = new StringBuilder(2048)
                .append("<p class=\"lead\">Verify that this code matches the one shown on your device. ")
                .append("Only approve a device you are setting up.</p>")
                .append("<div class=\"device-code\"><span>Activation code</span>")
                .append("<strong id=\"device-user-code\">")
                .append(DefaultBrowserPage.escapeHtml(userCode))
                .append("</strong></div><dl class=\"details\"><div><dt>Application</dt><dd>")
                .append(DefaultBrowserPage.escapeHtml(clientId))
                .append("</dd></div><div><dt>Signed in as</dt><dd>")
                .append(DefaultBrowserPage.escapeHtml(principal.getPrincipal().getName()))
                .append("</dd></div></dl>")
                .append("<form method=\"post\" action=\"")
                .append(DefaultBrowserPage.escapeHtml(context.request().path()))
                .append("\">");
        DefaultDeviceVerificationPage.hidden(page, OAuth2ParameterNames.CLIENT_ID, clientId);
        DefaultDeviceVerificationPage.hidden(page, OAuth2ParameterNames.USER_CODE, userCode);
        DefaultDeviceVerificationPage.hidden(page, OAuth2ParameterNames.STATE, state);
        DefaultDeviceVerificationPage.hidden(page, OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME,
                Boolean.TRUE.toString());

        if (!scopesToAuthorize.isEmpty()) {
            page.append("<fieldset><legend>Requested permissions</legend>");
        }
        for (String scope : scopesToAuthorize) {
            page.append("<label class=\"scope\"><input type=\"checkbox\" name=\"")
                    .append(OAuth2ParameterNames.SCOPE)
                    .append("\" value=\"").append(DefaultBrowserPage.escapeHtml(scope)).append("\"><span>")
                    .append(DefaultBrowserPage.escapeHtml(scope)).append("</span></label>");
        }
        if (!scopesToAuthorize.isEmpty()) {
            page.append("</fieldset>");
        }
        if (!previouslyAuthorizedScopes.isEmpty()) {
            page.append("<fieldset><legend>Permissions for this device:</legend>");
            for (String scope : previouslyAuthorizedScopes) {
                page.append("<label class=\"scope granted\"><input type=\"checkbox\" checked disabled><span>")
                        .append(DefaultBrowserPage.escapeHtml(scope)).append("</span></label>");
            }
            page.append("</fieldset>");
        }
        // Associate Deny with its own form so selected scopes are never submitted on rejection.
        page.append("<div class=\"actions\"><button type=\"submit\" id=\"submit-consent\">Approve</button>")
                .append("<button type=\"submit\" class=\"secondary\" id=\"cancel-consent\" form=\"device-denial\">Deny</button>")
                .append("</div></form><form id=\"device-denial\" method=\"post\" action=\"")
                .append(DefaultBrowserPage.escapeHtml(context.request().path())).append("\">");
        DefaultDeviceVerificationPage.hidden(page, OAuth2ParameterNames.CLIENT_ID, clientId);
        DefaultDeviceVerificationPage.hidden(page, OAuth2ParameterNames.USER_CODE, userCode);
        DefaultDeviceVerificationPage.hidden(page, OAuth2ParameterNames.STATE, state);
        DefaultDeviceVerificationPage.hidden(
                page,
                OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME,
                Boolean.FALSE.toString());
        page.append("</form>");
        DefaultBrowserPage.writeLocalForm(context, "Confirm your device", page.toString());
    }

    @Override
    public void displaySuccess(RoutingContext context, String clientId) {
        String body = "<p class=\"lead\">You may return to your device.</p>"
                + "<dl class=\"details\"><div><dt>Application</dt><dd>"
                + DefaultBrowserPage.escapeHtml(clientId) + "</dd></div></dl>";
        DefaultBrowserPage.writeLocalForm(context, "Device authorized", body);
    }

    @Override
    public void displayError(RoutingContext context, OAuth2Error error) {
        String body = "<p class=\"lead\">This device could not be authorized.</p>"
                + "<p class=\"error\" role=\"alert\">"
                + DefaultBrowserPage.escapeHtml(DefaultDeviceVerificationPage.message(error)) + "</p>"
                + "<dl class=\"details\"><div><dt>Error</dt><dd>"
                + DefaultBrowserPage.escapeHtml(error.getErrorCode()) + "</dd></div></dl>";
        DefaultBrowserPage.writeLocalForm(context, "Device verification failed", body);
    }

    private static void hidden(StringBuilder page, String name, String value) {
        page.append("<input type=\"hidden\" name=\"").append(DefaultBrowserPage.escapeHtml(name))
                .append("\" value=\"").append(DefaultBrowserPage.escapeHtml(value)).append("\">");
    }

    private static String message(OAuth2Error error) {
        return switch (error.getErrorCode()) {
            case "access_denied" -> "Device authorization was denied.";
            case "invalid_grant" ->
                "The activation code is invalid, expired, or has already been used.";
            default -> "The device verification request is invalid.";
        };
    }

}
