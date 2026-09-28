package io.quarkiverse.authorization.server.oidc.registration;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.oidc.OidcClientMetadataClaimNames;
import io.quarkus.arc.DefaultBean;

/**
 * Strict URI defaults composed with the application's scope policy. Replace
 * {@link ClientRegistrationScopeValidator} to accept scopes while retaining URI checks.
 * Supported capabilities and reserved registration scopes remain mandatory service checks.
 */
@Singleton
@DefaultBean
public final class OidcClientRegistrationValidator
        implements OidcClientRegistrationRequestValidator {
    private static final String ERROR_URI = "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError";

    public static final OidcClientRegistrationRequestValidator DEFAULT_REDIRECT_URI_VALIDATOR = context -> validateUris(
            context.request().getClientRegistration().getRedirectUris(),
            "invalid_redirect_uri",
            OidcClientMetadataClaimNames.REDIRECT_URIS);

    public static final OidcClientRegistrationRequestValidator DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR = context -> validateUris(
            context.request()
                    .getClientRegistration()
                    .getPostLogoutRedirectUris(),
            "invalid_client_metadata",
            OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);

    public static final OidcClientRegistrationRequestValidator DEFAULT_JWK_SET_URI_VALIDATOR = context -> {
        var url = context.request().getClientRegistration().getJwkSetUrl();
        if (url != null && !"https".equalsIgnoreCase(url.getProtocol())) {
            throw invalid("invalid_client_metadata", OidcClientMetadataClaimNames.JWKS_URI);
        }
    };

    private static final OidcClientRegistrationRequestValidator URI_VALIDATOR = DEFAULT_REDIRECT_URI_VALIDATOR
            .andThen(DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
            .andThen(DEFAULT_JWK_SET_URI_VALIDATOR);

    private final ClientRegistrationScopeValidator scopeValidator;

    @Inject
    public OidcClientRegistrationValidator(ClientRegistrationScopeValidator scopeValidator) {
        this.scopeValidator = java.util.Objects.requireNonNull(scopeValidator);
    }

    @Override
    public void validate(OidcClientRegistrationContext context) {
        URI_VALIDATOR.validate(context);
        var scopes = context.request().getClientRegistration().getScopes();
        this.scopeValidator.validate(scopes == null ? Set.of() : Set.copyOf(scopes));
    }

    private static void validateUris(List<String> values, String code, String parameter) {
        if (values == null) {
            return;
        }
        for (String value : values) {
            try {
                URI uri = new URI(value);
                String scheme = uri.getScheme();
                if (uri.getFragment() == null
                        && scheme != null
                        && !"javascript".equalsIgnoreCase(scheme)
                        && !"data".equalsIgnoreCase(scheme)
                        && !"vbscript".equalsIgnoreCase(scheme)) {
                    continue;
                }
            } catch (URISyntaxException ignored) {
                // Report the parameter name without reflecting untrusted input into the error
                // response.
            }
            throw invalid(code, parameter);
        }
    }

    private static OAuth2AuthenticationException invalid(String code, String parameter) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(code, "Invalid Client Registration: " + parameter, ERROR_URI));
    }
}
