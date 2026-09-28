package io.quarkiverse.authorization.server.oidc;

import java.io.Serial;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.token.AbstractOAuth2Token;

/**
 * An OpenID Connect ID Token containing claims about the resource owner's authentication.
 */
public class OidcIdToken extends AbstractOAuth2Token implements IdTokenClaimAccessor {

    @Serial
    private static final long serialVersionUID = -3626173100793739971L;

    private final Map<String, Object> claims;

    public OidcIdToken(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
        super(tokenValue, issuedAt, expiresAt);
        if (claims == null || claims.isEmpty()) {
            throw new IllegalArgumentException("claims cannot be empty");
        }
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    public static Builder withTokenValue(String tokenValue) {
        return new Builder(tokenValue);
    }

    public static final class Builder {

        private String tokenValue;
        private final Map<String, Object> claims = new LinkedHashMap<>();

        private Builder(String tokenValue) {
            this.tokenValue = tokenValue;
        }

        public Builder tokenValue(String tokenValue) {
            this.tokenValue = tokenValue;
            return this;
        }

        public Builder claim(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        public Builder claims(Consumer<Map<String, Object>> consumer) {
            consumer.accept(this.claims);
            return this;
        }

        public Builder issuer(String issuer) {
            return claim(IdTokenClaimNames.ISS, issuer);
        }

        public Builder subject(String subject) {
            return claim(IdTokenClaimNames.SUB, subject);
        }

        public Builder audience(Collection<String> audience) {
            return claim(IdTokenClaimNames.AUD, List.copyOf(audience));
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim(IdTokenClaimNames.IAT, issuedAt);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim(IdTokenClaimNames.EXP, expiresAt);
        }

        public Builder authTime(Instant authTime) {
            return claim(IdTokenClaimNames.AUTH_TIME, authTime);
        }

        public Builder nonce(String nonce) {
            return claim(IdTokenClaimNames.NONCE, nonce);
        }

        public Builder authorizedParty(String party) {
            return claim(IdTokenClaimNames.AZP, party);
        }

        public Builder authenticationContextClass(String acr) {
            return claim(IdTokenClaimNames.ACR, acr);
        }

        public Builder authenticationMethods(List<String> amr) {
            return claim(IdTokenClaimNames.AMR, amr);
        }

        public Builder accessTokenHash(String hash) {
            return claim(IdTokenClaimNames.AT_HASH, hash);
        }

        public Builder authorizationCodeHash(String hash) {
            return claim(IdTokenClaimNames.C_HASH, hash);
        }

        public OidcIdToken build() {
            return new OidcIdToken(this.tokenValue, timestamp(IdTokenClaimNames.IAT),
                    timestamp(IdTokenClaimNames.EXP), this.claims);
        }

        private Instant timestamp(String claim) {
            Object value = this.claims.get(claim);
            if (value != null && !(value instanceof Instant)) {
                throw new IllegalArgumentException("timestamps must be of type Instant");
            }
            return (Instant) value;
        }
    }
}
