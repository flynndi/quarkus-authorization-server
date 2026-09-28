package io.quarkiverse.authorization.server.it.multipleissuers;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/** Builds the same module with tenant routes and independent JDBC/key components. */
public class MultipleIssuersProfile implements QuarkusTestProfile {
    public String getConfigProfile() {
        return "multiple-issuers";
    }

    public Map<String, String> getConfigOverrides() {
        return Map.of("quarkus.authorization-server.issuer", "",
                "quarkus.authorization-server.issuers.alpha", "http://localhost:${quarkus.http.test-port:8081}/server/alpha",
                "quarkus.authorization-server.issuers.beta", "http://localhost:${quarkus.http.test-port:8081}/server/beta");
    }
}
