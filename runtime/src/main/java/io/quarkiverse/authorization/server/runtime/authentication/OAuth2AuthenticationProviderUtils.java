package io.quarkiverse.authorization.server.runtime.authentication;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.ClaimAccessor;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Shared protocol operations used by grant and token lifecycle providers.
 */
public final class OAuth2AuthenticationProviderUtils {

    private OAuth2AuthenticationProviderUtils() {
    }

    /** Requires client credentials; NONE carries identification only. */
    public static SecurityIdentity getAuthenticatedClientElseThrowInvalidClient(
            SecurityIdentity clientPrincipal) {
        getIdentifiedClientElseThrowInvalidClient(clientPrincipal);
        if (ClientAuthenticationMethod.NONE.equals(
                clientPrincipal.getAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE))) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return clientPrincipal;
    }

    public static SecurityIdentity getIdentifiedClientElseThrowInvalidClient(
            SecurityIdentity clientPrincipal) {
        RegisteredClient registeredClient = clientPrincipal != null
                ? clientPrincipal.getAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE)
                : null;
        if (clientPrincipal == null || clientPrincipal.isAnonymous() || registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return clientPrincipal;
    }

    /**
     * Attaches a newly generated access token and its issuance metadata. Generation
     * and persistence remain the caller's responsibility.
     */
    public static OAuth2AccessToken accessToken(OAuth2Authorization.Builder builder, OAuth2Token generatedToken,
            OAuth2TokenContext context) {
        DPoPTokenBinding.validateClaims(
                context,
                generatedToken instanceof ClaimAccessor accessor ? accessor.getClaims() : null);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                DPoPTokenBinding.tokenType(context),
                generatedToken.getTokenValue(),
                generatedToken.getIssuedAt(),
                generatedToken.getExpiresAt(),
                context.getAuthorizedScopes());
        builder.token(accessToken, metadata -> {
            metadata.put(OAuth2TokenFormat.class.getName(),
                    context.getRegisteredClient().getTokenSettings().getAccessTokenFormat().getValue());
            // Builder.token merges metadata from the previous token of the same type.
            // A new issuance must not inherit invalidation or claims from that token.
            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
            if (generatedToken instanceof ClaimAccessor claimAccessor) {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
            } else {
                metadata.remove(OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
            }
        });
        return accessToken;
    }
}
