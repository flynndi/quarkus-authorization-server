package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.PkceParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;

/** Verifies PKCE against the authorization request already loaded by the code exchange. */
final class PkceVerifier {
    private PkceVerifier() {
    }

    static void verify(
            AuthorizationCodeExchangeRequest request,
            RegisteredClient client,
            OAuth2AuthorizationRequest authorizationRequest) {
        Object value = request.getAdditionalParameters().get(PkceParameterNames.CODE_VERIFIER);
        if (value != null && (!(value instanceof String verifier) || verifier.isBlank())) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    PkceParameterNames.CODE_VERIFIER,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        String verifier = (String) value;
        String challenge = (String) authorizationRequest
                .getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE);
        boolean publicClient = ClientAuthenticationMethod.NONE.equals(
                request.getClientPrincipal()
                        .getAttribute(
                                OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE));
        if (challenge == null || challenge.isBlank()) {
            if (publicClient
                    || client.getClientSettings().isRequireProofKey()
                    || verifier != null) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            return;
        }

        Object method = authorizationRequest
                .getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if (verifier == null
                || !verifier.matches("[A-Za-z0-9._~-]{43,128}")
                || !"S256".equals(method)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            if (!MessageDigest.isEqual(
                    computed.getBytes(StandardCharsets.US_ASCII),
                    challenge.getBytes(StandardCharsets.US_ASCII))) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
