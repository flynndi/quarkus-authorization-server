package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class MultipleIssuersProactiveTest extends MultipleIssuersTestCases {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> MultipleIssuersTestSupport.application(jar, true));
}
