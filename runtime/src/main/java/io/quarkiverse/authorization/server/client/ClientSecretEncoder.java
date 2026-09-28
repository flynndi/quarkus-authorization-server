package io.quarkiverse.authorization.server.client;

/**
 * Encodes a newly registered Basic/POST client's secret before persistence. HMAC assertions retain
 * the original secret and do not invoke this encoder. A replacement must produce values
 * accepted by the application's {@link io.quarkiverse.authorization.server.client.ClientSecretVerifier}.
 */
@FunctionalInterface
public interface ClientSecretEncoder {
    String encode(String secret);
}
