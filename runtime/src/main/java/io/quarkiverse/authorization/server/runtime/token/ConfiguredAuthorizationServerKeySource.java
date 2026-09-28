package io.quarkiverse.authorization.server.runtime.token;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.logging.Logger;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig.SigningConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig.SigningKeyConfig;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkus.arc.DefaultBean;
import io.quarkus.runtime.LaunchMode;
import io.quarkus.runtime.util.StringUtil;
import io.smallrye.jwt.util.KeyUtils;

/** Loads PEM or ephemeral keys only when no application key source is supplied. */
@Singleton
@DefaultBean
public final class ConfiguredAuthorizationServerKeySource implements AuthorizationServerKeySource {
    private static final Logger LOG = Logger.getLogger(ConfiguredAuthorizationServerKeySource.class);
    private final SigningConfig config;

    @Inject
    public ConfiguredAuthorizationServerKeySource(AuthorizationServerRuntimeConfig config) {
        this.config = config.signing();
    }

    @Override
    public KeySet load() {
        if (config.keys().isEmpty()) {
            if (config.activeKeyId().isPresent())
                throw new IllegalStateException(
                        "quarkus.authorization-server.signing.active-key-id requires signing.keys");
            var keys = singleSigningKeys(config);
            if (keys.isEmpty()) {
                Key key = generateDefaultSigningKey();
                keys = Map.of(key.keyId(), key);
                if (LaunchMode.current() == LaunchMode.NORMAL)
                    LOG.warn(
                            "No authorization server signing key was configured. An ephemeral RSA"
                                    + " signing key was generated; tokens issued by this instance"
                                    + " cannot be verified after restart and may not be valid across"
                                    + " multiple instances.");
            }
            return new KeySet(List.copyOf(keys.values()), null);
        }
        if (isSingleKeyConfigured(config))
            throw new IllegalStateException(
                    "Single signing key properties cannot be combined with"
                            + " quarkus.authorization-server.signing.keys");
        return new KeySet(
                List.copyOf(configuredSigningKeys(config.keys()).values()),
                config.activeKeyId().orElse(null));
    }

    private static Key signingKey(
            String keyId,
            SignatureAlgorithm algorithm,
            String privateKeyLocation,
            String publicKeyLocation) {
        return new Key(
                keyId,
                algorithm,
                privateKeyLocation == null ? null : readPrivateKey(privateKeyLocation, algorithm),
                readPublicKey(publicKeyLocation, algorithm));
    }

    private static Map<String, Key> singleSigningKeys(SigningConfig config) {
        if (!isSingleKeyConfigured(config)) {
            return Map.of();
        }
        String keyId = required(
                config.keyId().orElse(null),
                "quarkus.authorization-server.signing.key-id must be configured");
        String privateKeyLocation = required(
                config.privateKeyLocation().orElse(null),
                "quarkus.authorization-server.signing.private-key-location must be"
                        + " configured");
        String publicKeyLocation = required(
                config.publicKeyLocation().orElse(null),
                "quarkus.authorization-server.signing.public-key-location must be"
                        + " configured");
        SignatureAlgorithm algorithm = signatureAlgorithm(config.algorithm());
        Key signingKey = signingKey(keyId, algorithm, privateKeyLocation, publicKeyLocation);
        return Map.of(keyId, signingKey);
    }

    private static Map<String, Key> configuredSigningKeys(
            Map<String, SigningKeyConfig> keyConfigs) {
        Map<String, Key> signingKeys = new LinkedHashMap<>();
        keyConfigs.forEach(
                (keyId, config) -> {
                    String requiredKeyId = required(keyId, "Signing key id cannot be blank");
                    String publicKeyLocation = required(
                            config.publicKeyLocation().orElse(null),
                            "Public key location must be configured for signing key '"
                                    + requiredKeyId
                                    + "'");
                    SignatureAlgorithm algorithm = signatureAlgorithm(config.algorithm());
                    signingKeys.put(
                            requiredKeyId,
                            signingKey(
                                    requiredKeyId,
                                    algorithm,
                                    config.privateKeyLocation().orElse(null),
                                    publicKeyLocation));
                });
        return Collections.unmodifiableMap(signingKeys);
    }

    private static Key generateDefaultSigningKey() {
        try {
            KeyPair keyPair = KeyUtils.generateKeyPair(2048);
            return new Key(
                    UUID.randomUUID().toString(),
                    SignatureAlgorithm.RS256,
                    keyPair.getPrivate(),
                    keyPair.getPublic());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to generate the default authorization server signing key", exception);
        }
    }

    private static SignatureAlgorithm signatureAlgorithm(String value) {
        SignatureAlgorithm algorithm = SignatureAlgorithm.from(value.toUpperCase(Locale.ROOT));
        if (algorithm == null) {
            throw new IllegalStateException("Unsupported signing algorithm '" + value + "'");
        }
        return algorithm;
    }

    private static PrivateKey readPrivateKey(String location, SignatureAlgorithm algorithm) {
        try {
            byte[] encoded = decodePem(read(location), "PRIVATE KEY");
            return KeyFactory.getInstance(keyFactoryAlgorithm(algorithm))
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Unable to load private key from '" + location + "'", exception);
        }
    }

    private static PublicKey readPublicKey(String location, SignatureAlgorithm algorithm) {
        try {
            byte[] encoded = decodePem(read(location), "PUBLIC KEY");
            return KeyFactory.getInstance(keyFactoryAlgorithm(algorithm))
                    .generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Unable to load public key from '" + location + "'", exception);
        }
    }

    private static String keyFactoryAlgorithm(SignatureAlgorithm algorithm) {
        return algorithm.getName().startsWith("ES") ? "EC" : "RSA";
    }

    private static String read(String location) throws IOException {
        if (location.startsWith("classpath:")) {
            String resourceName = location.substring("classpath:".length());
            resourceName = StringUtil.changePrefix(resourceName, "/", "");
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            try (InputStream input = classLoader.getResourceAsStream(resourceName)) {
                if (input == null) {
                    throw new IOException("Classpath resource does not exist");
                }
                return new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        Path path = location.startsWith("file:") ? Path.of(URI.create(location)) : Path.of(location);
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static byte[] decodePem(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int beginIndex = pem.indexOf(begin);
        int endIndex = pem.indexOf(end);
        if (beginIndex < 0 || endIndex < 0 || endIndex <= beginIndex) {
            throw new IllegalArgumentException("Expected PEM " + type);
        }
        String encoded = pem.substring(beginIndex + begin.length(), endIndex).replaceAll("\\s", "");
        return Base64.getDecoder().decode(encoded);
    }

    private static boolean isSingleKeyConfigured(SigningConfig config) {
        return config.keyId().isPresent()
                || config.privateKeyLocation().isPresent()
                || config.publicKeyLocation().isPresent();
    }

    private static String required(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(message);
        }
        return value;
    }
}
