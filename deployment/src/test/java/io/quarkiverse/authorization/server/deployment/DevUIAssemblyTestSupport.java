package io.quarkiverse.authorization.server.deployment;

import java.security.KeyPairGenerator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;

final class DevUIAssemblyTestSupport {
    public static final class OnceKeySource implements AuthorizationServerKeySource {
        private final String id;
        private final AtomicInteger loads = new AtomicInteger();

        public OnceKeySource(String id) {
            this.id = id;
        }

        @Override
        public KeySet load() {
            if (this.loads.incrementAndGet() != 1) {
                throw new IllegalStateException("Dev UI must never reload signing keys");
            }
            try {
                var generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                var pair = generator.generateKeyPair();
                return new KeySet(List.of(new Key(this.id, SignatureAlgorithm.RS256, pair.getPrivate(), pair.getPublic())),
                        this.id);
            } catch (java.security.GeneralSecurityException exception) {
                throw new IllegalStateException(exception);
            }
        }
    }

    public static final class UnqueriedClients implements RegisteredClientRepository {
        @Override
        public void save(RegisteredClient client) {
            throw new AssertionError("Dev UI must not write clients");
        }

        @Override
        public RegisteredClient findById(String id) {
            throw new AssertionError("Dev UI must not query clients");
        }

        @Override
        public RegisteredClient findByClientId(String id) {
            throw new AssertionError("Dev UI must not query clients");
        }
    }

}
