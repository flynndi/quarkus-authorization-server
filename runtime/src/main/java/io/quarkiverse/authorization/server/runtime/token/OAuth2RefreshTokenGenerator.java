package io.quarkiverse.authorization.server.runtime.token;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

/**
 * Generates an {@link OAuth2RefreshToken}.
 */
public final class OAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private static final int REFRESH_TOKEN_LENGTH_BYTES = 96;

    private final SecureRandom refreshTokenRandom = new SecureRandom();

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        if (isPublicClient(context) && !context.hasKey(DPoPProof.class)) {
            return null;
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        byte[] bytes = new byte[REFRESH_TOKEN_LENGTH_BYTES];
        this.refreshTokenRandom.nextBytes(bytes);
        String tokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
    }

    private static boolean isPublicClient(OAuth2TokenContext context) {
        Object authorizationGrant = context.getAuthorizationGrant();
        if (!(authorizationGrant instanceof TokenGrantRequest authentication)) {
            return false;
        }
        ClientAuthenticationMethod clientAuthenticationMethod = authentication.getClientPrincipal().getAttribute(
                OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE);
        return ClientAuthenticationMethod.NONE.equals(clientAuthenticationMethod);
    }
}
