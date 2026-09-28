package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class LazyAuthorizationInteractionTest extends AbstractAuthorizationInteractionTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> AuthorizationInteractionTestSupport.application(jar, false));
}
