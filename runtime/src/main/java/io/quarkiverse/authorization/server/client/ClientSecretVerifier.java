package io.quarkiverse.authorization.server.client;

/**
 * CDI contract for verifying a presented client secret against its stored representation.
 */
public interface ClientSecretVerifier {

    boolean matches(String presentedSecret, String storedSecret);
}
