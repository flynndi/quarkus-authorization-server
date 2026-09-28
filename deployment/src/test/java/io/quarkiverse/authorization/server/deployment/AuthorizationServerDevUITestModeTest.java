package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.runtime.devui.AuthorizationServerDevUIService;
import io.quarkus.arc.Arc;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;

class AuthorizationServerDevUITestModeTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest().withEmptyApplication();

    @Test
    void doesNotExposeDevelopmentDataInOrdinaryTestMode() {
        Assertions.assertFalse(Arc.container().instance(AuthorizationServerDevUIService.class).isAvailable());
        RestAssured.get("/oauth2/jwks").then().statusCode(200);
        RestAssured.get("/q/dev-ui/quarkus-authorization-server-data.js").then().statusCode(404);
        RestAssured.get("/q/dev-ui/quarkus-authorization-server/qwc-authorization-server-overview.js").then().statusCode(404);
    }
}
