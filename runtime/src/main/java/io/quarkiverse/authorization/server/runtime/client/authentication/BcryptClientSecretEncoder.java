package io.quarkiverse.authorization.server.runtime.client.authentication;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.ClientSecretEncoder;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class BcryptClientSecretEncoder implements ClientSecretEncoder {
    @Override
    public String encode(String secret) {
        return io.quarkus.elytron.security.common.BcryptUtil.bcryptHash(secret);
    }
}
