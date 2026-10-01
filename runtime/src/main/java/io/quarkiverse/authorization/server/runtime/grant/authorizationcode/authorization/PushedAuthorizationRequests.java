package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;

/** PAR persistence using the existing authorization repository; no browser or client credentials are stored. */
final class PushedAuthorizationRequests {
    static final String URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    private static final long LIFETIME_SECONDS = 300;

    private final OAuth2AuthorizationService authorizations;
    private final SecureRandom random = new SecureRandom();

    PushedAuthorizationRequests(OAuth2AuthorizationService authorizations) {
        this.authorizations = authorizations;
    }

    PushedAuthorizationResponse save(AuthorizationRequest request, RegisteredClient client) {
        byte[] bytes = new byte[32];
        this.random.nextBytes(bytes);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        var parameters = new LinkedHashMap<>(request.getAdditionalParameters());
        parameters.remove(OAuth2ParameterNames.CLIENT_SECRET);
        parameters.remove(OAuth2ParameterNames.CLIENT_ASSERTION);
        parameters.remove(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);
        var savedRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(request.getAuthorizationUri()).clientId(client.getClientId())
                .redirectUri(request.getRedirectUri()).scopes(request.getScopes()).state(request.getState())
                .additionalParameters(parameters).build();
        this.authorizations.save(OAuth2Authorization.withRegisteredClient(client).id(id)
                .principalName(client.getClientId()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2AuthorizationRequest.class.getName(), savedRequest)
                .attribute(OAuth2AuthorizationRequest.PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME,
                        Instant.now().plusSeconds(LIFETIME_SECONDS))
                .build());
        // Use the record id, not consent's state index: a PAR reference cannot be submitted as consent state.
        return new PushedAuthorizationResponse(URI_PREFIX + id, LIFETIME_SECONDS);
    }

    Resolved resolve(AuthorizationRequest reference) {
        Object value = reference.getAdditionalParameters().get(OAuth2ParameterNames.REQUEST_URI);
        if (!(value instanceof String uri) || !uri.startsWith(URI_PREFIX)
                || !uri.substring(URI_PREFIX.length()).matches("[A-Za-z0-9_-]{43}")) {
            throw PushedAuthorizationRequests.invalidReference();
        }
        OAuth2Authorization authorization = this.authorizations.findById(uri.substring(URI_PREFIX.length()));
        if (authorization == null
                || !(authorization.getAttribute(
                        OAuth2AuthorizationRequest.PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME) instanceof Instant expiresAt)
                || !(authorization
                        .getAttribute(OAuth2AuthorizationRequest.class.getName()) instanceof OAuth2AuthorizationRequest request)
                || !request.getClientId().equals(reference.getClientId())) {
            throw PushedAuthorizationRequests.invalidReference();
        }
        if (!Instant.now().isBefore(expiresAt)) {
            this.authorizations.remove(authorization);
            throw PushedAuthorizationRequests.invalidReference();
        }
        return new Resolved(authorization, new AuthorizationRequest(reference.getAuthorizationUri(), request.getClientId(),
                reference.getPrincipal(), request.getRedirectUri(), request.getState(), request.getScopes(),
                request.getAdditionalParameters()));
    }

    void consume(Resolved resolved) {
        if (resolved != null)
            this.authorizations.remove(resolved.authorization());
    }

    static AuthorizationRequestException invalidReference() {
        // Never select a callback from an untrusted or expired reference.
        return new AuthorizationRequestException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                "OAuth 2.0 Parameter: " + OAuth2ParameterNames.REQUEST_URI, "https://www.rfc-editor.org/rfc/rfc9126#section-4"),
                null);
    }

    record Resolved(OAuth2Authorization authorization, AuthorizationRequest request) {
    }
}
