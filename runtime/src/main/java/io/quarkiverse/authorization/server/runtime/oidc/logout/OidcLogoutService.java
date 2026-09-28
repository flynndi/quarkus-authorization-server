package io.quarkiverse.authorization.server.runtime.oidc.logout;

import java.util.List;
import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.IdTokenClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutContext;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutRequest;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutRequestValidator;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

/**
 * Validates an OIDC logout request; the HTTP adapter owns application session lookup and logout.
 */
@Singleton
public final class OidcLogoutService {
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OidcLogoutRequestValidator requestValidator;

    @Inject
    public OidcLogoutService(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OidcLogoutRequestValidator requestValidator) {

        this.registeredClientRepository = Objects.requireNonNull(registeredClientRepository);
        this.authorizationService = Objects.requireNonNull(authorizationService);
        this.requestValidator = Objects.requireNonNull(requestValidator, "logoutValidator cannot be null");
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public OidcLogoutResult validate(OidcLogoutRequest request) {
        Objects.requireNonNull(request, "request cannot be null");
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                request.getIdTokenHint(), ID_TOKEN_TOKEN_TYPE);
        if (authorization == null) {
            throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
        }
        OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
        // Logout accepts expired ID Tokens, but rejects invalidated or not-yet-valid tokens.
        if (authorizedIdToken == null
                || authorizedIdToken.isInvalidated()
                || authorizedIdToken.isBeforeUse()
                || !request.getIdTokenHint().equals(authorizedIdToken.getToken().getTokenValue())) {
            throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
        }
        RegisteredClient registeredClient = this.registeredClientRepository.findById(authorization.getRegisteredClientId());
        if (registeredClient == null) {
            throwError(OAuth2ErrorCodes.INVALID_TOKEN, OAuth2ParameterNames.CLIENT_ID);
        }
        OidcIdToken idToken = authorizedIdToken.getToken();
        List<String> audience = idToken.getAudience();
        if (audience == null || !audience.contains(registeredClient.getClientId())) {
            throwError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.AUD);
        }
        if (Arguments.hasText(request.getClientId())
                && !request.getClientId().equals(registeredClient.getClientId())) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
        }
        this.requestValidator.validate(new OidcLogoutContext(request, registeredClient));
        if (!request.getPrincipal().isAnonymous()) {
            // sub may be customized. Bind the current identity to the authorization's canonical
            // resource owner.
            if (!Arguments.hasText(idToken.getSubject())
                    || !request.getPrincipal()
                            .getPrincipal()
                            .getName()
                            .equals(authorization.getPrincipalName())) {
                throwError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.SUB);
            }
            if (Arguments.hasText(request.getSessionId())
                    && !request.getSessionId().equals(idToken.getClaimAsString("sid"))) {
                throwError(OAuth2ErrorCodes.INVALID_TOKEN, "sid");
            }
        }
        return new OidcLogoutResult(
                request.getPrincipal(), request.getPostLogoutRedirectUri(), request.getState());
    }

    private static void throwError(String code, String parameter) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(
                        code,
                        "OpenID Connect 1.0 Logout Request Parameter: " + parameter,
                        "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling"));
    }
}
