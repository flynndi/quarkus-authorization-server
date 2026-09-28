package io.quarkiverse.authorization.server.runtime.dpop;

import java.util.Map;
import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.dpop.DPoPReplayStore;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkus.security.identity.SecurityIdentity;

/** Shared token binding rules. Callers retain ownership of authorization checks and persistence. */
@Singleton
public final class DPoPTokenBinding {
    public static final String CNF = "cnf";
    public static final String JKT = "jkt";
    public static final String REFRESH_JKT_METADATA = DPoPTokenBinding.class.getName() + ".refresh-jkt";
    private final DPoPProofVerifier verifier;
    private final DPoPReplayStore replay;

    @Inject
    public DPoPTokenBinding(DPoPProofVerifier verifier, DPoPReplayStore replay) {
        this.verifier = Objects.requireNonNull(verifier);
        this.replay = Objects.requireNonNull(replay);
    }

    /** A stored code/refresh binding cannot be dropped by omitting the header. */
    public DPoPProof verify(DPoPProofRequest request, String expectedJkt) {
        if (request == null) {
            if (expectedJkt != null)
                throw DPoPProofVerifier.invalidProof();
            return null;
        }
        DPoPProof proof = verifier.verify(request);
        if (expectedJkt != null && !expectedJkt.equals(proof.jwkThumbprint()))
            throw DPoPProofVerifier.invalidProof();
        return proof;
    }

    /** Resource authentication checks both the token hash and its persisted public key binding. */
    public DPoPProof verifyAccessToken(
            DPoPProofRequest request, OAuth2Authorization.Token<OAuth2AccessToken> token) {
        String expectedJkt = accessTokenThumbprint(token);
        if (request == null)
            throw DPoPProofVerifier.invalidProof();
        DPoPProof proof = verifier.verify(request, token.getToken().getTokenValue());
        if (!expectedJkt.equals(proof.jwkThumbprint()))
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        return proof;
    }

    /**
     * A DPoP token must have consistent type and cnf.jkt metadata, including after JDBC loading.
     */
    public static String accessTokenThumbprint(OAuth2Authorization.Token<OAuth2AccessToken> token) {
        if (!OAuth2AccessToken.TokenType.DPOP.equals(token.getToken().getTokenType())
                || token.getClaims() == null
                || !(token.getClaims().get(CNF) instanceof Map<?, ?> confirmation)
                || !(confirmation.get(JKT) instanceof String thumbprint)
                || !thumbprint.matches("[A-Za-z0-9_-]{43}"))
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        return thumbprint;
    }

    /** Invoke only after the relevant authorization/token and stored-key checks have passed. */
    public void claim(DPoPProofRequest request, DPoPProof proof) {
        if (proof != null
                && !replay.claim(new DPoPReplayStore.Key(request.uri(), proof.jwkThumbprint(), proof.jwtId()),
                        proof.expiresAt()))
            throw DPoPProofVerifier.invalidProof();
    }

    /** Initial public refresh tokens must be bound even when supplied by a custom generator. */
    public static void bindRefreshToken(
            OAuth2Authorization.Builder authorization,
            OAuth2RefreshToken refreshToken,
            SecurityIdentity clientPrincipal,
            DPoPProof proof) {
        boolean publicClient = ClientAuthenticationMethod.NONE.equals(
                clientPrincipal.getAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE));
        if (publicClient && proof == null)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        authorization.token(
                refreshToken,
                metadata -> {
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
                    if (publicClient)
                        metadata.put(REFRESH_JKT_METADATA, proof.jwkThumbprint());
                    else
                        metadata.remove(REFRESH_JKT_METADATA);
                });
    }

    public static Map<String, String> confirmation(OAuth2TokenContext context) {
        DPoPProof proof = context.get(DPoPProof.class);
        return proof == null ? null : Map.of(JKT, proof.jwkThumbprint());
    }

    public static OAuth2AccessToken.TokenType tokenType(OAuth2TokenContext context) {
        return context.hasKey(DPoPProof.class)
                ? OAuth2AccessToken.TokenType.DPOP
                : OAuth2AccessToken.TokenType.BEARER;
    }

    /** Check after customization, and again when attaching a custom generator's result. */
    public static void validateClaims(OAuth2TokenContext context, Map<String, Object> claims) {
        Map<String, String> expected = confirmation(context);
        Object actual = claims == null ? null : claims.get(CNF);
        if (!Objects.equals(expected, actual))
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
    }

    /**
     * Bearer-only consumers must also reject claims-bound tokens with inconsistent type metadata.
     */
    public static boolean isBound(OAuth2Authorization.Token<?> token) {
        return token.getToken() instanceof OAuth2AccessToken access
                && OAuth2AccessToken.TokenType.DPOP.equals(access.getTokenType())
                || token.getClaims() != null && token.getClaims().containsKey(CNF);
    }
}
