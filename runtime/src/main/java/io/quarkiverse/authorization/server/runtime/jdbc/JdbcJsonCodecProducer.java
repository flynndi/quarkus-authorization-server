package io.quarkiverse.authorization.server.runtime.jdbc;

import java.util.List;

import jakarta.enterprise.inject.Default;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonValueAdapter;
import io.quarkus.arc.All;
import io.quarkus.arc.DefaultBean;

/** Storage JSON has its own contract and does not consume application ObjectMapper customizers. */
@Singleton
public class JdbcJsonCodecProducer {

    @Produces
    @Singleton
    @DefaultBean
    public JdbcJsonCodec jsonCodec(@All @Default List<JdbcJsonValueAdapter<?>> adapters) {
        return new JdbcJsonCodec(adapters);
    }
}
