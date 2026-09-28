package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;

import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.oidc.OidcUserInfo;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoContext;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoMapper;
import io.quarkus.test.QuarkusUnitTest;

class DisabledOidcPolicyTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest().withApplicationRoot(jar -> jar.addClass(Mapper.class));

    @Test
    void unusedPolicyDoesNotEnableOidcOrGetConsumed() {
        given().get("/.well-known/openid-configuration").then().statusCode(404);
        given().get("/userinfo").then().statusCode(404);
    }

    @Singleton
    public static class Mapper implements OidcUserInfoMapper {
        public Mapper() {
            throw new AssertionError("Disabled OIDC must not instantiate its application mapper");
        }

        public OidcUserInfo map(OidcUserInfoContext context) {
            throw new AssertionError("Unused mapper");
        }
    }
}
