package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;

class AuthorizationServerJackson2IsolationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest();

    @Inject
    ObjectMapper applicationObjectMapper;

    @Test
    void doesNotRegisterPersistenceModuleWithApplicationObjectMapper() throws Exception {
        Map<String, Object> values = Collections.unmodifiableMap(new HashMap<>(Map.of("ttl", Duration.ofMinutes(5))));

        String applicationJson = this.applicationObjectMapper.writeValueAsString(values);

        assertFalse(applicationJson.contains("@class"));
        assertNull(this.applicationObjectMapper.findMixInClassFor(QuarkusSecurityIdentity.class));
        assertNull(this.applicationObjectMapper.findMixInClassFor(QuarkusPrincipal.class));
    }
}
