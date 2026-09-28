package io.quarkiverse.authorization.server.metadata;

import java.net.URL;
import java.util.List;

import io.quarkiverse.authorization.server.token.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for OAuth 2.0 Authorization Server Metadata claims.
 */
public interface OAuth2AuthorizationServerMetadataClaimAccessor extends ClaimAccessor {

    default URL getIssuer() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.ISSUER);
    }

    default URL getAuthorizationEndpoint() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT);
    }

    default URL getDeviceAuthorizationEndpoint() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT);
    }

    default URL getTokenEndpoint() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT);
    }

    default List<String> getTokenEndpointAuthenticationMethods() {
        return getClaimAsStringList(
                OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED);
    }

    default List<String> getTokenEndpointAuthenticationSigningAlgorithms() {
        return getClaimAsStringList(
                OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED);
    }

    default List<String> getTokenIntrospectionEndpointAuthenticationSigningAlgorithms() {
        return getClaimAsStringList(
                OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED);
    }

    default List<String> getTokenRevocationEndpointAuthenticationSigningAlgorithms() {
        return getClaimAsStringList(
                OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED);
    }

    default URL getJwkSetUrl() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI);
    }

    default List<String> getScopes() {
        return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED);
    }

    default List<String> getResponseTypes() {
        return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
    }

    default List<String> getGrantTypes() {
        return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED);
    }

    default URL getTokenRevocationEndpoint() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT);
    }

    default List<String> getTokenRevocationEndpointAuthenticationMethods() {
        return getClaimAsStringList(
                OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED);
    }

    default URL getTokenIntrospectionEndpoint() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT);
    }

    default List<String> getTokenIntrospectionEndpointAuthenticationMethods() {
        return getClaimAsStringList(
                OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED);
    }

    default URL getClientRegistrationEndpoint() {
        return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT);
    }

    default List<String> getCodeChallengeMethods() {
        return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED);
    }

    default List<String> getDPoPSigningAlgorithms() {
        return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED);
    }

}
