package io.quarkiverse.authorization.server.runtime.dpop;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;

import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig.DPoPConfig;

/**
 * Core RFC 9449 proof checks, including ath for resource access. The caller checks key binding,
 * then registers the proof in DPoPReplayStore. No token issuance or HTTP response is performed
 * here.
 */
@Singleton
public final class DPoPProofVerifier {
    private static final int MAX_JTI_LENGTH = 256;
    private static final Set<String> PRIVATE_JWK_MEMBERS = Set.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");
    private final AlgorithmConstraints algorithms;
    private final Duration maxAge;
    private final Duration clockSkew;
    private final int maxLength;
    private final Clock clock;

    @Inject
    public DPoPProofVerifier(AuthorizationServerRuntimeConfig config) {
        this(config.dpop(), Clock.systemUTC());
    }

    DPoPProofVerifier(DPoPConfig config, Clock clock) {
        if (config.proofAlgorithms().isEmpty())
            throw new IllegalArgumentException("dpop.proof-algorithms must not be empty");
        maxAge = config.proofMaxAge();
        clockSkew = config.clockSkew();
        if (maxAge.isNegative() || maxAge.isZero() || clockSkew.isNegative())
            throw new IllegalArgumentException(
                    "dpop.proof-max-age must be positive and clock-skew nonnegative");
        maxLength = config.maxProofLength();
        if (maxLength <= 0)
            throw new IllegalArgumentException("dpop.max-proof-length must be positive");
        algorithms = new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.PERMIT,
                config.proofAlgorithms().stream()
                        .map(a -> a.getName())
                        .toArray(String[]::new));
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Synchronous crypto: the HTTP caller supplies a Quarkus worker/request-context boundary. */
    public DPoPProof verify(DPoPProofRequest request) {
        return verifyProof(request, null);
    }

    /** Resource access additionally binds the signed proof to the exact access token value. */
    public DPoPProof verify(DPoPProofRequest request, String accessToken) {
        return verifyProof(request, Objects.requireNonNull(accessToken, "accessToken"));
    }

    private DPoPProof verifyProof(DPoPProofRequest request, String accessToken) {
        Objects.requireNonNull(request, "request");
        try {
            String compact = request.proof();
            if (compact.length() > maxLength
                    || !compact.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"))
                throw invalidProof();
            JsonWebSignature jws = new JsonWebSignature();
            jws.setAlgorithmConstraints(algorithms);
            jws.setCompactSerialization(compact);
            Map<String, Object> headers = JsonUtil.parseJson(jws.getHeaders().getFullHeaderAsJsonString());
            if (!"dpop+jwt".equals(headers.get("typ"))
                    || headers.containsKey("crit")
                    || headers.containsKey("b64"))
                throw invalidProof();
            if (!(headers.get("jwk") instanceof Map<?, ?> jwk)
                    || jwk.keySet().stream().anyMatch(PRIVATE_JWK_MEMBERS::contains))
                throw invalidProof();
            // JsonUtil accepts only string JSON member names, including nested objects.
            @SuppressWarnings("unchecked")
            Map<String, Object> publicJwk = (Map<String, Object>) jwk;
            PublicJsonWebKey key = PublicJsonWebKey.Factory.newPublicJwk(publicJwk);
            if (key.getPrivateKey() != null)
                throw invalidProof();
            jws.setKey(key.getPublicKey());
            if (!jws.verifySignature())
                throw invalidProof();
            Map<String, Object> claims = JsonUtil.parseJson(jws.getPayload());
            if (!request.method().equals(claims.get("htm"))
                    || !(claims.get("htu") instanceof String target))
                throw invalidProof();
            URI uri = URI.create(target);
            if (uri.getRawQuery() != null
                    || uri.getRawFragment() != null
                    || !DPoPProofRequest.canonicalUri(uri).equals(request.uri()))
                throw invalidProof();
            if (accessToken != null) {
                String expectedHash = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(
                                                accessToken.getBytes(
                                                        StandardCharsets.US_ASCII)));
                if (!(claims.get("ath") instanceof String hash)
                        || !MessageDigest.isEqual(
                                expectedHash.getBytes(StandardCharsets.US_ASCII),
                                hash.getBytes(StandardCharsets.UTF_8)))
                    throw invalidProof();
            }
            return validateReplayClaims(key.calculateBase64urlEncodedThumbprint("SHA-256"), claims);
        } catch (OAuth2AuthenticationException exception) {
            throw exception;
        } catch (Exception exception) {
            // Do not retain attacker-controlled JWTs or library exception messages in protocol
            // errors.
            throw invalidProof();
        }
    }

    /**
     * Checks only jti/iat after a trusted component has verified the JWT and its key/token binding.
     * This lets an OIDC SecurityIdentityAugmentor add replay protection without re-verifying
     * signatures. Unauthenticated input must go through verify instead. This method does not
     * register a use.
     */
    public DPoPProof validateReplayClaims(
            String verifiedJwkThumbprint, Map<String, Object> verifiedClaims) {
        try {
            if (verifiedJwkThumbprint == null
                    || !verifiedJwkThumbprint.matches("[A-Za-z0-9_-]{43}")
                    || !(verifiedClaims.get("jti") instanceof String id)
                    || id.isBlank()
                    || id.length() > MAX_JTI_LENGTH
                    || !(verifiedClaims.get("iat") instanceof Number number))
                throw invalidProof();
            BigDecimal date = new BigDecimal(number.toString());
            BigDecimal seconds = date.setScale(0, RoundingMode.FLOOR);
            Instant issuedAt = Instant.ofEpochSecond(
                    seconds.longValueExact(),
                    date.subtract(seconds).movePointRight(9).longValueExact());
            Instant now = clock.instant();
            Instant expiresAt = issuedAt.plus(maxAge);
            if (issuedAt.isAfter(now.plus(clockSkew)) || !now.isBefore(expiresAt))
                throw invalidProof();
            return new DPoPProof(verifiedJwkThumbprint, id, expiresAt);
        } catch (OAuth2AuthenticationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidProof();
        }
    }

    static OAuth2AuthenticationException invalidProof() {
        return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
    }
}
