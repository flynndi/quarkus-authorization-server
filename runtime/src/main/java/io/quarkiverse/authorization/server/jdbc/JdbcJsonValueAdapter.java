package io.quarkiverse.authorization.server.jdbc;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Explicit storage binding for an application value. Implementations must be thread-safe and
 * validate their payload when reading. The stable ID must start with {@code custom:};
 * it must not be derived from a Java class name or the application release version.
 * Jackson bean binding and automatic class loading are not used by the persistence codec.
 * Payloads must fit the codec's Jackson read constraints, which are also enforced before writing succeeds.
 */
public interface JdbcJsonValueAdapter<T> {

    String typeId();

    /** Exact runtime class handled by this adapter; subclass matching is intentionally unsupported. */
    Class<T> javaType();

    JsonNode write(T value);

    T read(JsonNode value);
}
