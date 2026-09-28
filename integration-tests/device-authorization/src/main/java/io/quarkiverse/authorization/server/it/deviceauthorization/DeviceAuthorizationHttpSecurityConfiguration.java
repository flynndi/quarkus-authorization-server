package io.quarkiverse.authorization.server.it.deviceauthorization;

import jakarta.enterprise.event.Observes;

import io.quarkus.vertx.http.security.HttpSecurity;

/** Selects Form for the browser endpoint while the same application also installs OIDC Bearer. */
public final class DeviceAuthorizationHttpSecurityConfiguration {

    void configure(@Observes HttpSecurity httpSecurity) {
        httpSecurity.get("/oauth2/device_verification").form().authenticated();
        httpSecurity.post("/oauth2/device_verification").form().authenticated();
    }
}
