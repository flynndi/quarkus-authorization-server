package io.quarkiverse.authorization.server.token;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;

/** CDI source loaded once by the key manager. The manager validates every source identically. */
@FunctionalInterface
public interface AuthorizationServerKeySource {
    KeySet load();

    /** A null private key represents a verification-only key. */
    record Key(
            String keyId,
            SignatureAlgorithm algorithm,
            PrivateKey privateKey,
            PublicKey publicKey) {
    }

    /** A null active key id is allowed only when exactly one key is provided. */
    record KeySet(List<Key> keys, String activeKeyId) {
        public KeySet {
            keys = List.copyOf(keys);
        }
    }
}
