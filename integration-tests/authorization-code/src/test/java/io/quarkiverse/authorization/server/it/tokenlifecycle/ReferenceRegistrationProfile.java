package io.quarkiverse.authorization.server.it.tokenlifecycle;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

public class ReferenceRegistrationProfile implements QuarkusTestProfile {
    public String getConfigProfile() {
        return "reference-registration";
    }

    public Map<String, String> getConfigOverrides() {
        return Map.of("quarkus.authorization-server.issuer", "http://localhost:${quarkus.http.test-port:8081}");
    }
}
