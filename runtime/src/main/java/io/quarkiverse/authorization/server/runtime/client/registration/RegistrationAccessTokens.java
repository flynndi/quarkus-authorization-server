package io.quarkiverse.authorization.server.runtime.client.registration;

import java.util.Set;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Shared initial/registration access-token checks and sequential invalidation.
 */
public final class RegistrationAccessTokens {

    private RegistrationAccessTokens() {
    }

    public static OAuth2Authorization getAccessTokenAuthorization(
            SecurityIdentity principal, OAuth2AuthorizationService service, String requiredScope) {
        TokenCredential credential = principal.getCredential(TokenCredential.class);
        if (principal.isAnonymous()
                || credential == null
                || !"bearer".equals(credential.getType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        OAuth2Authorization authorization = service.findByToken(credential.getToken(), OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null
                || authorization.getAccessToken() == null
                || !authorization.getAccessToken().isActive()
                || !credential
                        .getToken()
                        .equals(authorization.getAccessToken().getToken().getTokenValue())
                || !authorization.getPrincipalName().equals(principal.getPrincipal().getName())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        Set<String> scopes = authorization.getAccessToken().getToken().getScopes();
        if (!scopes.contains(requiredScope)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
        }
        if (scopes.size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        return authorization;
    }

    public static OAuth2Authorization invalidate(OAuth2Authorization authorization) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization)
                .token(
                        authorization.getAccessToken().getToken(),
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                true));
        if (authorization.getRefreshToken() != null) {
            builder.token(
                    authorization.getRefreshToken().getToken(),
                    metadata -> metadata.put(
                            OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        }
        return builder.build();
    }

}
