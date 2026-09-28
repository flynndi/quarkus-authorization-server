package io.quarkiverse.authorization.server.runtime.oidc.registration;

import java.util.Collection;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.oidc.OidcClientMetadataClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetCache;

/**
 * Mandatory registration capability checks. Parameter validation is a separate CDI policy;
 * replacing it cannot enable unsupported protocols or accept server-issued credentials as input.
 */
public final class OidcClientRegistrationMetadataValidator {

    private static final String ERROR_URI = "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError";
    private static final Set<String> REQUEST_CLAIMS = Set.of(
            OidcClientMetadataClaimNames.CLIENT_NAME,
            OidcClientMetadataClaimNames.REDIRECT_URIS,
            OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS,
            OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD,
            OidcClientMetadataClaimNames.GRANT_TYPES,
            OidcClientMetadataClaimNames.RESPONSE_TYPES,
            OidcClientMetadataClaimNames.SCOPE,
            OidcClientMetadataClaimNames.JWKS_URI,
            OidcClientMetadataClaimNames.TLS_CLIENT_AUTH_SUBJECT_DN,
            OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG,
            OidcClientMetadataClaimNames.ID_TOKEN_SIGNED_RESPONSE_ALG);
    private static final Set<String> AUTHENTICATION_METHODS = Set.of(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
            ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(),
            ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
            ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue(),
            ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue(),
            ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue(),
            ClientAuthenticationMethod.NONE.getValue());
    private static final Set<String> GRANT_TYPES = Set.of(
            AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
            AuthorizationGrantType.PASSWORD.getValue(),
            AuthorizationGrantType.REFRESH_TOKEN.getValue(),
            AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
            AuthorizationGrantType.DEVICE_CODE.getValue(),
            AuthorizationGrantType.TOKEN_EXCHANGE.getValue());

    private final Set<SignatureAlgorithm> signingAlgorithms;

    /**
     * @param signingAlgorithms algorithms backed by usable signing private keys, not enum values
     */
    public OidcClientRegistrationMetadataValidator(
            Collection<SignatureAlgorithm> signingAlgorithms) {
        this.signingAlgorithms = Set.copyOf(signingAlgorithms);
    }

    /**
     * Capability and reserved-claim checks are mandatory even when an application replaces
     * parameter validation.
     */
    public void validateSupportedMetadata(OidcClientRegistration registration) {
        for (String claim : registration.getClaims().keySet()) {
            if (!REQUEST_CLAIMS.contains(claim)) {
                // Do not silently discard an unsupported setting or persist attacker-supplied
                // credentials.
                throw invalidMetadata(claim);
            }
        }

        String authenticationMethod = registration.getTokenEndpointAuthenticationMethod();
        if (authenticationMethod != null && !AUTHENTICATION_METHODS.contains(authenticationMethod)) {
            throw OidcClientRegistrationMetadataValidator
                    .invalidMetadata(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
        }
        boolean privateJwt = ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod);
        boolean selfSigned = ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue().equals(authenticationMethod);
        String authenticationAlgorithm = registration.getTokenEndpointAuthenticationSigningAlgorithm();
        if (authenticationAlgorithm != null && !(privateJwt && SignatureAlgorithm.from(authenticationAlgorithm) != null)
                && !(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(authenticationMethod)
                        && MacAlgorithm.from(authenticationAlgorithm) != null)) {
            throw OidcClientRegistrationMetadataValidator
                    .invalidMetadata(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
        }
        if (privateJwt || selfSigned) {
            try {
                ClientJwkSetCache.validateJwkSetUrl(registration.getJwkSetUrl() == null
                        ? null
                        : registration.getJwkSetUrl().toString());
            } catch (IllegalArgumentException exception) {
                throw OidcClientRegistrationMetadataValidator.invalidMetadata(OidcClientMetadataClaimNames.JWKS_URI);
            }
        } else if (registration.getClaims().containsKey(OidcClientMetadataClaimNames.JWKS_URI)) {
            throw OidcClientRegistrationMetadataValidator.invalidMetadata(OidcClientMetadataClaimNames.JWKS_URI);
        }
        if (ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue().equals(authenticationMethod)) {
            Object subject = registration.getClaims().get(OidcClientMetadataClaimNames.TLS_CLIENT_AUTH_SUBJECT_DN);
            try {
                if (!(subject instanceof String dn) || dn.isBlank())
                    throw new IllegalArgumentException();
                new javax.security.auth.x500.X500Principal(dn);
            } catch (IllegalArgumentException exception) {
                throw OidcClientRegistrationMetadataValidator
                        .invalidMetadata(OidcClientMetadataClaimNames.TLS_CLIENT_AUTH_SUBJECT_DN);
            }
        } else if (registration.getClaims().containsKey(OidcClientMetadataClaimNames.TLS_CLIENT_AUTH_SUBJECT_DN)) {
            throw OidcClientRegistrationMetadataValidator
                    .invalidMetadata(OidcClientMetadataClaimNames.TLS_CLIENT_AUTH_SUBJECT_DN);
        }
        if (registration.getGrantTypes() != null
                && !GRANT_TYPES.containsAll(registration.getGrantTypes())) {
            throw invalidMetadata(OidcClientMetadataClaimNames.GRANT_TYPES);
        }
        if (registration.getResponseTypes() != null
                && registration.getResponseTypes().stream()
                        .anyMatch(
                                type -> !OAuth2AuthorizationResponseType.CODE
                                        .getValue()
                                        .equals(type))) {
            throw invalidMetadata(OidcClientMetadataClaimNames.RESPONSE_TYPES);
        }
        if (ClientAuthenticationMethod.NONE.getValue().equals(authenticationMethod)
                && registration.getGrantTypes() != null
                && registration
                        .getGrantTypes()
                        .contains(AuthorizationGrantType.PASSWORD.getValue())) {
            // The current public-client authentication path requires an authorization code and
            // PKCE.
            throw invalidMetadata(OidcClientMetadataClaimNames.GRANT_TYPES);
        }
        if (registration.getScopes() != null) {
            for (String scope : registration.getScopes()) {
                if (scope.isEmpty()
                        || !scope.chars()
                                .allMatch(
                                        character -> character == 0x21
                                                || character >= 0x23 && character <= 0x5B
                                                || character >= 0x5D && character <= 0x7E)
                        || "client.create".equals(scope)
                        || "client.read".equals(scope)) {
                    throw invalidMetadata(OidcClientMetadataClaimNames.SCOPE);
                }
            }
        }
        SignatureAlgorithm signingAlgorithm = registration.getIdTokenSignedResponseAlgorithm() != null
                ? SignatureAlgorithm.from(registration.getIdTokenSignedResponseAlgorithm())
                : SignatureAlgorithm.RS256;
        if (signingAlgorithm == null || !this.signingAlgorithms.contains(signingAlgorithm)) {
            throw invalidMetadata(OidcClientMetadataClaimNames.ID_TOKEN_SIGNED_RESPONSE_ALG);
        }
    }

    private static OAuth2AuthenticationException invalidMetadata(String claim) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(
                        "invalid_client_metadata",
                        "Invalid Client Registration: " + claim,
                        ERROR_URI));
    }
}
