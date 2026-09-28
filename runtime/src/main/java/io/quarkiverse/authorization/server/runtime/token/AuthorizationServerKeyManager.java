package io.quarkiverse.authorization.server.runtime.token;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jose4j.keys.BigEndianBigInteger;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkus.arc.DefaultBean;

/** Validates source keys, selects signing keys and exposes public JWK representations. */
@Singleton
@DefaultBean
public final class AuthorizationServerKeyManager {

    private static final byte[] KEY_PAIR_VALIDATION_MESSAGE = "quarkus-authorization-server"
            .getBytes(StandardCharsets.US_ASCII);

    private final Supplier<AuthorizationServerKeyManager> delegate;
    private final Map<String, SigningKey> signingKeys;
    private final SigningKey activeSigningKey;

    public static AuthorizationServerKeyManager delegating(Supplier<AuthorizationServerKeyManager> delegate) {
        return new AuthorizationServerKeyManager(delegate);
    }

    private AuthorizationServerKeyManager(Supplier<AuthorizationServerKeyManager> delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate);
        this.signingKeys = null;
        this.activeSigningKey = null;
    }

    @Inject
    public AuthorizationServerKeyManager(AuthorizationServerKeySource source) {
        this.delegate = null;
        var loaded = java.util.Objects.requireNonNull(source.load(), "Signing key source returned null");
        var keys = new LinkedHashMap<String, SigningKey>();
        for (var key : loaded.keys()) {
            String id = required(key.keyId(), "Signing key id cannot be blank");
            java.util.Objects.requireNonNull(
                    key.algorithm(), "Signing key algorithm cannot be null");
            java.util.Objects.requireNonNull(key.publicKey(), "Signing public key cannot be null");
            if (keys.containsKey(id))
                throw new IllegalStateException("Duplicate signing key id '" + id + "'");
            keys.put(id, signingKey(id, key.algorithm(), key.privateKey(), key.publicKey()));
        }
        if (keys.isEmpty())
            throw new IllegalStateException("Signing key source must provide at least one key");
        this.signingKeys = Collections.unmodifiableMap(keys);
        this.activeSigningKey = selectActiveSigningKey(Optional.ofNullable(loaded.activeKeyId()), keys);
        if (this.activeSigningKey.privateKey() == null)
            throw new IllegalStateException(
                    "The active authorization server signing key must include a private key");
        // Fail at startup if algorithm-based selection would otherwise be ambiguous on an ID Token
        // request.
        getSigningAlgorithms();
    }

    public SignatureAlgorithm getAlgorithm() {
        return getActiveSigningKey().algorithm();
    }

    public String getKeyId() {
        return getActiveSigningKey().keyId();
    }

    public PrivateKey getPrivateKey() {
        return getActiveSigningKey().privateKey();
    }

    public PublicKey getPublicKey() {
        return getActiveSigningKey().publicKey();
    }

    public List<Map<String, Object>> getPublicJwks() {
        if (this.delegate != null)
            return this.delegate.get().getPublicJwks();
        return this.signingKeys.values().stream()
                .map(AuthorizationServerKeyManager::publicJwk)
                .toList();
    }

    /**
     * Algorithms for which this instance can select a signing private key, not verification-only
     * keys.
     */
    public List<SignatureAlgorithm> getSigningAlgorithms() {
        if (this.delegate != null)
            return this.delegate.get().getSigningAlgorithms();
        List<SignatureAlgorithm> algorithms = this.signingKeys.values().stream()
                .filter(key -> key.privateKey() != null)
                .map(SigningKey::algorithm)
                .distinct()
                .toList();
        algorithms.forEach(this::getSigningKey);
        return algorithms;
    }

    SigningKey getSigningKey(SignatureAlgorithm algorithm) {
        if (this.delegate != null)
            return this.delegate.get().getSigningKey(algorithm);
        if (this.activeSigningKey.algorithm().equals(algorithm)) {
            return this.activeSigningKey;
        }
        List<SigningKey> candidates = this.signingKeys.values().stream()
                .filter(
                        key -> key.privateKey() != null
                                && key.algorithm().equals(algorithm))
                .toList();
        if (candidates.size() != 1) {
            throw new IllegalStateException(
                    "Expected one signing private key for "
                            + algorithm
                            + " when the active key uses another algorithm; found "
                            + candidates.size());
        }
        return candidates.get(0);
    }

    SigningKey getSigningKey(String keyId, String algorithm) {
        if (this.delegate != null)
            return this.delegate.get().getSigningKey(keyId, algorithm);
        SigningKey key = this.signingKeys.get(keyId);
        if (key == null
                || key.privateKey() == null
                || !key.algorithm().getName().equals(algorithm)) {
            throw new IllegalStateException(
                    "JWT header must select an available signing key with its configured"
                            + " algorithm");
        }
        return key;
    }

    private SigningKey getActiveSigningKey() {
        if (this.delegate != null)
            return this.delegate.get().getActiveSigningKey();
        return this.activeSigningKey;
    }

    private static SigningKey selectActiveSigningKey(
            Optional<String> activeKeyId, Map<String, SigningKey> signingKeys) {
        if (activeKeyId.isEmpty()) {
            if (signingKeys.size() == 1) {
                return signingKeys.values().iterator().next();
            }
            throw new IllegalStateException(
                    "quarkus.authorization-server.signing.active-key-id must be configured when"
                            + " multiple signing keys exist");
        }
        SigningKey signingKey = signingKeys.get(activeKeyId.get());
        if (signingKey == null) {
            throw new IllegalStateException(
                    "The active signing key '" + activeKeyId.get() + "' does not exist");
        }
        return signingKey;
    }

    private static SigningKey signingKey(
            String keyId,
            SignatureAlgorithm algorithm,
            PrivateKey privateKey,
            PublicKey publicKey) {
        validateKeyType(algorithm, privateKey, publicKey);
        if (privateKey != null) {
            validateKeyPair(algorithm, privateKey, publicKey);
        }
        return new SigningKey(keyId, algorithm, privateKey, publicKey);
    }

    private static void validateKeyType(
            SignatureAlgorithm algorithm, PrivateKey privateKey, PublicKey publicKey) {
        if (algorithm.getName().startsWith("ES")) {
            if (!(publicKey instanceof ECPublicKey ecPublicKey)
                    || (privateKey != null && !(privateKey instanceof ECPrivateKey))) {
                throw new IllegalStateException(
                        "Signing algorithm " + algorithm.getName() + " requires EC keys");
            }
            validateCurve(algorithm, ecPublicKey.getParams());
            return;
        }
        if (!(publicKey instanceof RSAPublicKey)
                || (privateKey != null && !(privateKey instanceof RSAPrivateKey))) {
            throw new IllegalStateException(
                    "Signing algorithm " + algorithm.getName() + " requires RSA keys");
        }
    }

    private static void validateCurve(SignatureAlgorithm algorithm, ECParameterSpec actual) {
        String curveName = curveName(algorithm);
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(standardCurveName(algorithm)));
            ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
            if (!expected.getCurve().equals(actual.getCurve())
                    || !expected.getGenerator().equals(actual.getGenerator())
                    || !expected.getOrder().equals(actual.getOrder())
                    || expected.getCofactor() != actual.getCofactor()) {
                throw new IllegalStateException(
                        "Signing algorithm "
                                + algorithm.getName()
                                + " requires the "
                                + curveName
                                + " curve");
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to validate the " + curveName + " curve", exception);
        }
    }

    private static void validateKeyPair(
            SignatureAlgorithm algorithm, PrivateKey privateKey, PublicKey publicKey) {
        try {
            Signature signer = signature(algorithm);
            signer.initSign(privateKey);
            signer.update(KEY_PAIR_VALIDATION_MESSAGE);
            byte[] signatureValue = signer.sign();

            Signature verifier = signature(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(KEY_PAIR_VALIDATION_MESSAGE);
            if (!verifier.verify(signatureValue)) {
                throw new IllegalStateException(
                        "The configured private and public signing keys do not match");
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to validate the configured signing key pair", exception);
        }
    }

    private static Signature signature(SignatureAlgorithm algorithm)
            throws GeneralSecurityException {
        Signature signature = switch (algorithm) {
            case RS256 -> Signature.getInstance("SHA256withRSA");
            case RS384 -> Signature.getInstance("SHA384withRSA");
            case RS512 -> Signature.getInstance("SHA512withRSA");
            case ES256 -> Signature.getInstance("SHA256withECDSA");
            case ES384 -> Signature.getInstance("SHA384withECDSA");
            case ES512 -> Signature.getInstance("SHA512withECDSA");
            case PS256, PS384, PS512 -> Signature.getInstance("RSASSA-PSS");
        };
        if (algorithm == SignatureAlgorithm.PS256) {
            signature.setParameter(
                    new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        } else if (algorithm == SignatureAlgorithm.PS384) {
            signature.setParameter(
                    new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1));
        } else if (algorithm == SignatureAlgorithm.PS512) {
            signature.setParameter(
                    new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
        }
        return signature;
    }

    private static Map<String, Object> publicJwk(SigningKey signingKey) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        PublicKey publicKey = signingKey.publicKey();
        // JWK integers omit BigInteger's sign byte; EC coordinates must also retain the curve's fixed width.
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            jwk.put("kty", "RSA");
            jwk.put("n", BigEndianBigInteger.toBase64Url(rsaPublicKey.getModulus()));
            jwk.put("e", BigEndianBigInteger.toBase64Url(rsaPublicKey.getPublicExponent()));
        } else if (publicKey instanceof ECPublicKey ecPublicKey) {
            int coordinateSize = (ecPublicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            jwk.put("kty", "EC");
            jwk.put("crv", curveName(signingKey.algorithm()));
            jwk.put("x", BigEndianBigInteger.toBase64Url(ecPublicKey.getW().getAffineX(), coordinateSize));
            jwk.put("y", BigEndianBigInteger.toBase64Url(ecPublicKey.getW().getAffineY(), coordinateSize));
        } else {
            throw new IllegalStateException("Unsupported public signing key type");
        }
        jwk.put("use", "sig");
        jwk.put("alg", signingKey.algorithm().getName());
        jwk.put("kid", signingKey.keyId());
        return Collections.unmodifiableMap(jwk);
    }

    private static String curveName(SignatureAlgorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> "P-256";
            case ES384 -> "P-384";
            case ES512 -> "P-521";
            default -> throw new IllegalStateException("Unexpected EC signing algorithm");
        };
    }

    private static String standardCurveName(SignatureAlgorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> "secp256r1";
            case ES384 -> "secp384r1";
            case ES512 -> "secp521r1";
            default -> throw new IllegalStateException("Unexpected EC signing algorithm");
        };
    }

    private static String required(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(message);
        }
        return value;
    }

    record SigningKey(
            String keyId,
            SignatureAlgorithm algorithm,
            PrivateKey privateKey,
            PublicKey publicKey) {
    }
}
