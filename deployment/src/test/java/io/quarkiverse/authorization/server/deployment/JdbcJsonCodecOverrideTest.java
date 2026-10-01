package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkus.test.QuarkusUnitTest;

class JdbcJsonCodecOverrideTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(ApplicationCodec.class, JdbcJsonCodecAdaptersTest.class,
                    JdbcJsonCodecAdaptersTest.Value.class, JdbcJsonCodecAdaptersTest.ValueAdapter.class,
                    JdbcJsonCodecAdaptersTest.SeparateCodecAdapter.class));

    @Inject
    JdbcJsonCodec codec;

    @Test
    void applicationProducerReplacesTheDefaultAssembly() {
        Map<String, Object> values = Map.of("ordinary", "value");
        assertEquals(values,
                this.codec.readAuthorizationAttributes("alice", this.codec.writeAuthorizationAttributes("alice", values)));
        // The application explicitly selected a codec without adapters despite an adapter Bean being present.
        assertThrows(IllegalArgumentException.class, () -> this.codec.writeAuthorizationAttributes("alice",
                Map.of("business", new JdbcJsonCodecAdaptersTest.Value("value"))));
    }

    @Singleton
    public static class ApplicationCodec {
        @Produces
        @Singleton
        public JdbcJsonCodec codec() {
            return new JdbcJsonCodec();
        }
    }
}
