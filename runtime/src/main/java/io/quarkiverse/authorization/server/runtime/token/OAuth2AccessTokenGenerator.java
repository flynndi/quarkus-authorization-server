package io.quarkiverse.authorization.server.runtime.token;

import java.io.Serial;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.ClaimAccessor;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsSet;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

/** Generates high-entropy reference (opaque) access tokens for the shared token generator. */
public final class OAuth2AccessTokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {
    private static final int TOKEN_BYTES = 96;
    private final SecureRandom secureRandom = new SecureRandom();
    private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || !OAuth2TokenFormat.REFERENCE
                        .equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
        OAuth2TokenClaimsSet.Builder claims = OAuth2TokenClaimsSet.builder();
        if (context.getAuthorizationServerContext() != null
                && context.getAuthorizationServerContext().getIssuer() != null
                && !context.getAuthorizationServerContext().getIssuer().isBlank()) {
            claims.issuer(context.getAuthorizationServerContext().getIssuer());
        }
        claims.subject(context.getPrincipal().getPrincipal().getName())
                .audience(List.of(context.getRegisteredClient().getClientId()))
                .issuedAt(issuedAt).expiresAt(expiresAt).notBefore(issuedAt).id(UUID.randomUUID().toString());
        if (!context.getAuthorizedScopes().isEmpty()) {
            claims.claim("scope", context.getAuthorizedScopes());
        }
        if (DPoPTokenBinding.confirmation(context) != null)
            claims.claim(DPoPTokenBinding.CNF, DPoPTokenBinding.confirmation(context));
        if (this.accessTokenCustomizer != null) {
            OAuth2TokenClaimsContext.Builder customizerContext = OAuth2TokenClaimsContext.with(claims)
                    .registeredClient(context.getRegisteredClient()).principal(context.getPrincipal())
                    .authorizationServerContext(context.getAuthorizationServerContext())
                    .authorizedScopes(context.getAuthorizedScopes()).tokenType(context.getTokenType())
                    .authorizationGrantType(context.getAuthorizationGrantType());
            if (context.getAuthorization() != null)
                customizerContext.authorization(context.getAuthorization());
            if (context.getAuthorizationGrant() != null)
                customizerContext.authorizationGrant(context.getAuthorizationGrant());
            if (context.hasKey(DPoPProof.class))
                customizerContext.put(DPoPProof.class, context.get(DPoPProof.class));
            this.accessTokenCustomizer.customize(customizerContext.build());
        }
        OAuth2TokenClaimsSet claimSet = claims.build();
        DPoPTokenBinding.validateClaims(context, claimSet.getClaims());
        byte[] bytes = new byte[TOKEN_BYTES];
        this.secureRandom.nextBytes(bytes);
        return new OAuth2AccessTokenClaims(
                DPoPTokenBinding.tokenType(context),
                Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
                issuedAt,
                expiresAt,
                context.getAuthorizedScopes(),
                claimSet.getClaims());
    }

    public void setAccessTokenCustomizer(OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
        this.accessTokenCustomizer = Objects.requireNonNull(
                accessTokenCustomizer, "accessTokenCustomizer cannot be null");
    }

    private static final class OAuth2AccessTokenClaims extends OAuth2AccessToken implements ClaimAccessor {

        @Serial
        private static final long serialVersionUID = -81307444138144489L;

        private final Map<String, Object> claims;

        private OAuth2AccessTokenClaims(TokenType type, String value, Instant issuedAt, Instant expiresAt,
                Set<String> scopes, Map<String, Object> claims) {
            super(type, value, issuedAt, expiresAt, scopes);
            this.claims = claims;
        }

        @Override
        public Map<String, Object> getClaims() {
            return this.claims;
        }
    }
}
