package io.quarkiverse.authorization.server.runtime.client;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.ClientSecretVerifier;
import io.quarkus.arc.DefaultBean;
import io.quarkus.elytron.security.common.BcryptUtil;

/**
 * Default client secret verifier backed by bcrypt.
 */
@Singleton
@DefaultBean
public final class BcryptClientSecretVerifier implements ClientSecretVerifier {

    @Override
    public boolean matches(String presentedSecret, String storedSecret) {
        if (presentedSecret == null || presentedSecret.isEmpty() || storedSecret == null || storedSecret.isBlank()) {
            return false;
        }
        try {
            return BcryptUtil.matches(presentedSecret, storedSecret);
        } catch (RuntimeException ignored) {
            // BcryptUtil throws for malformed hashes; client authentication treats them as a non-match.
            return false;
        }
    }
}
