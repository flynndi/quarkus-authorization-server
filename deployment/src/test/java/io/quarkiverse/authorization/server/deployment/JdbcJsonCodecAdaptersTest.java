package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;

import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonValueAdapter;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.common.annotation.Identifier;

class JdbcJsonCodecAdaptersTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(Value.class, ValueAdapter.class, SeparateCodecAdapter.class));

    @Inject
    JdbcJsonCodec codec;

    @Inject
    @Identifier("separate-codec")
    SeparateCodecAdapter separateCodecAdapter;

    @Test
    void defaultCodecDiscoversTypedApplicationAdapters() {
        // Keep the qualified bean reachable: it is intentionally for another codec, not a duplicate default binding.
        assertNotNull(this.separateCodecAdapter);
        Map<String, Object> attributes = Map.of("business", new Value("value"));
        String json = this.codec.writeAuthorizationAttributes("alice", attributes);
        assertTrue(json.contains("custom:business-value"));
        assertFalse(json.contains(Value.class.getName()));
        assertEquals(attributes, this.codec.readAuthorizationAttributes("alice", json));
    }

    public record Value(String value) {
    }

    @Singleton
    @Identifier("separate-codec")
    public static class SeparateCodecAdapter extends ValueAdapter {
    }

    @Singleton
    public static class ValueAdapter implements JdbcJsonValueAdapter<Value> {
        @Override
        public String typeId() {
            return "custom:business-value";
        }

        @Override
        public Class<Value> javaType() {
            return Value.class;
        }

        @Override
        public JsonNode write(Value value) {
            return TextNode.valueOf(value.value());
        }

        @Override
        public Value read(JsonNode value) {
            if (!value.isTextual()) {
                throw new IllegalArgumentException("Expected business value text");
            }
            return new Value(value.textValue());
        }
    }
}
