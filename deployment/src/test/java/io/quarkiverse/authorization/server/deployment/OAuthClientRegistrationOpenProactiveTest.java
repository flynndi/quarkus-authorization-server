package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class OAuthClientRegistrationOpenProactiveTest extends OAuthClientRegistrationOpenTestSupport {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = OAuthClientRegistrationOpenTestSupport.application(true);
}
