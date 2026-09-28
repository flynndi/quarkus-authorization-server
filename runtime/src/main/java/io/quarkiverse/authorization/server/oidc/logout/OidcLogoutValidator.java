package io.quarkiverse.authorization.server.oidc.logout;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.arc.DefaultBean;

/**
 * Default CDI policy for validating logout parameters. The logout service always checks
 * ID Token, client and session binding.
 */
@Singleton
@DefaultBean
public final class OidcLogoutValidator implements OidcLogoutRequestValidator {
    public static final OidcLogoutRequestValidator DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR = context -> {
        String redirectUri = context.request().getPostLogoutRedirectUri();
        if (redirectUri != null
                && !redirectUri.isBlank()
                && !context.registeredClient()
                        .getPostLogoutRedirectUris()
                        .contains(redirectUri)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "OpenID Connect 1.0 Logout Request Parameter:"
                                    + " post_logout_redirect_uri",
                            "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling"));
        }
    };

    @Override
    public void validate(OidcLogoutContext context) {
        DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR.validate(context);
    }
}
