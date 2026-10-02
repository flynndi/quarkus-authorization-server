package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.jackson.ObjectMapperCustomizer;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;

class JdbcJsonCodecIsolationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(ApplicationJson.class, ApplicationLongSerializer.class));

    @Inject
    ObjectMapper applicationMapper;

    @Inject
    JdbcJsonCodec codec;

    @Test
    void storageIgnoresApplicationCustomizersAndDoesNotModifyApplicationMapper() throws Exception {
        Map<String, Object> values = Map.of("counter", 123L);
        assertTrue(this.applicationMapper.writeValueAsString(values).contains("application-value"));
        String stored = this.codec.writeAuthorizationAttributes("alice", values);
        assertFalse(stored.contains("application-value"));
        assertEquals(values, this.codec.readAuthorizationAttributes("alice", stored));
        assertTrue(this.codec.writeTokenSettings(TokenSettings.builder().build()).contains("accessTokenTimeToLive"));
        assertFalse(this.applicationMapper.writeValueAsString(values).contains("@class"));
        assertNull(this.applicationMapper.findMixInClassFor(QuarkusSecurityIdentity.class));
        assertNull(this.applicationMapper.findMixInClassFor(QuarkusPrincipal.class));
        assertNull(this.applicationMapper.getDeserializationConfig().getDefaultTyper(null));
    }

    @Singleton
    public static class ApplicationJson implements ObjectMapperCustomizer {
        @Override
        public void customize(ObjectMapper mapper) {
            mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
            SimpleModule module = new SimpleModule();
            module.addSerializer(Long.class, new ApplicationLongSerializer());
            mapper.registerModule(module);
        }
    }

    public static class ApplicationLongSerializer extends JsonSerializer<Long> {
        @Override
        public void serialize(Long value, JsonGenerator generator, SerializerProvider provider) throws IOException {
            generator.writeString("application-value");
        }
    }
}
