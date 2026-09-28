package io.quarkiverse.authorization.server.token;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * JSON Web Signature headers used when encoding a JWT.
 */
public final class JwsHeader {

    private final Map<String, Object> headers;

    private JwsHeader(Map<String, Object> headers) {
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    public String getAlgorithm() {
        return (String) this.headers.get("alg");
    }

    public String getKeyId() {
        return (String) this.headers.get("kid");
    }

    public String getType() {
        return (String) this.headers.get("typ");
    }

    public Map<String, Object> getHeaders() {
        return this.headers;
    }

    public static Builder with(String algorithm) {
        return new Builder().algorithm(algorithm);
    }

    public static final class Builder {

        private final Map<String, Object> headers = new LinkedHashMap<>();

        public Builder algorithm(String algorithm) {
            return header("alg", Arguments.requireNonBlank(algorithm, "algorithm"));
        }

        public Builder keyId(String keyId) {
            return header("kid", Arguments.requireNonBlank(keyId, "keyId"));
        }

        public Builder type(String type) {
            return header("typ", Arguments.requireNonBlank(type, "type"));
        }

        public Builder header(String name, Object value) {
            this.headers.put(
                    Arguments.requireNonBlank(name, "name"),
                    Objects.requireNonNull(value, "value cannot be null"));
            return this;
        }

        public Builder headers(Consumer<Map<String, Object>> headersConsumer) {
            Objects.requireNonNull(headersConsumer, "headersConsumer cannot be null").accept(this.headers);
            return this;
        }

        public JwsHeader build() {
            if (!this.headers.containsKey("alg")) {
                throw new IllegalArgumentException("algorithm cannot be empty");
            }
            return new JwsHeader(this.headers);
        }
    }
}
