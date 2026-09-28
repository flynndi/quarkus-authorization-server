package io.quarkiverse.authorization.server.oidc;

import java.net.URL;
import java.time.Instant;
import java.util.List;

/**
 * Typed access to the authentication claims in an ID Token.
 */
public interface IdTokenClaimAccessor extends StandardClaimAccessor {

    default URL getIssuer() {
        return getClaimAsURL(IdTokenClaimNames.ISS);
    }

    default String getSubject() {
        return getClaimAsString(IdTokenClaimNames.SUB);
    }

    default List<String> getAudience() {
        return getClaimAsStringList(IdTokenClaimNames.AUD);
    }

    default Instant getExpiresAt() {
        return getClaimAsInstant(IdTokenClaimNames.EXP);
    }

    default Instant getIssuedAt() {
        return getClaimAsInstant(IdTokenClaimNames.IAT);
    }

    default Instant getAuthenticatedAt() {
        return getClaimAsInstant(IdTokenClaimNames.AUTH_TIME);
    }

    default String getNonce() {
        return getClaimAsString(IdTokenClaimNames.NONCE);
    }

    default String getAuthenticationContextClass() {
        return getClaimAsString(IdTokenClaimNames.ACR);
    }

    default List<String> getAuthenticationMethods() {
        return getClaimAsStringList(IdTokenClaimNames.AMR);
    }

    default String getAuthorizedParty() {
        return getClaimAsString(IdTokenClaimNames.AZP);
    }

    default String getAccessTokenHash() {
        return getClaimAsString(IdTokenClaimNames.AT_HASH);
    }

    default String getAuthorizationCodeHash() {
        return getClaimAsString(IdTokenClaimNames.C_HASH);
    }
}
