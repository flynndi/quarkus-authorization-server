package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;

import java.util.List;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.oidc.OidcUserInfo;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoContext;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoMapper;
import io.quarkus.test.QuarkusUnitTest;

class OidcUserInfoMapperTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> UserInfoTestApplication.application(jar)
                            .addClasses(
                                    UserInfoMapper.class,
                                    PolicyRequestProbe.class,
                                    PolicyRequestProbe.Observations.class));

    @Inject
    PolicyRequestProbe.Observations observations;
    @Inject
    Instance<OidcClientRegistrationValidator> registrationPolicies;

    @org.junit.jupiter.api.BeforeEach
    void clearObservations() {
        this.observations.clear();
    }

    @Test
    void nullMapperResultReturnsServerErrorAndReleasesRequestScope() {
        String access = tokens("openid");
        given().auth()
                .oauth2(access)
                .header("x-test-null-mapper", "true")
                .get("/me")
                .then()
                .statusCode(500)
                .body("error", equalTo("server_error"));
        this.observations.assertReleased(List.of("userinfo-mapper"));
    }

    @Test
    void selectsApplicationMapperThroughCdiAfterProtocolValidation() {
        org.junit.jupiter.api.Assertions.assertFalse(this.registrationPolicies.isResolvable());
        String access = tokens("openid email");
        given().auth()
                .oauth2(access)
                .get("/me")
                .then()
                .statusCode(200)
                .body("sub", equalTo("resource-owner"))
                .body("customized", equalTo(true))
                .body("$", not(hasKey("email")));
        this.observations.assertReleased(List.of("userinfo-mapper"));
        String withoutOpenid = tokens("email");
        given().auth()
                .oauth2(withoutOpenid)
                .get("/me")
                .then()
                .statusCode(403)
                .body("error", equalTo("insufficient_scope"));
    }

    private static String tokens(String scope) {
        return given().auth()
                .preemptive()
                .basic("client", "client-secret")
                .contentType(io.restassured.http.ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .formParam("scope", scope)
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
    }

    @Singleton
    public static class UserInfoMapper implements OidcUserInfoMapper {
        @Inject
        PolicyRequestProbe request;
        @Inject
        io.vertx.ext.web.RoutingContext http;

        public OidcUserInfo map(OidcUserInfoContext context) {
            this.request.visit("userinfo-mapper");
            org.junit.jupiter.api.Assertions.assertEquals("/api/me", this.http.request().path());
            org.junit.jupiter.api.Assertions.assertSame(
                    context.principal(),
                    ((io.quarkus.vertx.http.runtime.security.QuarkusHttpUser) this.http.user())
                            .getSecurityIdentity());
            if ("true".equals(this.http.request().getHeader("x-test-null-mapper")))
                return null;
            return OidcUserInfo.builder()
                    .subject(context.authorization().getPrincipalName())
                    .claim("customized", context.accessToken().getScopes().contains("openid"))
                    .build();
        }
    }
}
