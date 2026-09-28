package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.lang.reflect.Proxy;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.vertx.http.runtime.FormAuthConfig;

class DefaultLoginPageTest {
    @Test
    void rejectsMissingOrNonlocalPageLocations() {
        for (String login : new String[] { "", "https://external.example/login", "//external.example/login",
                "/login#fragment" }) {
            Assertions.assertThrows(ConfigurationException.class,
                    () -> new DefaultLoginPage(DefaultLoginPageTest.config(login, "/error", "/check")));
        }
    }

    @Test
    void acceptsQuarkusPageConventionsAndDisabledErrorRedirect() {
        Assertions.assertDoesNotThrow(() -> new DefaultLoginPage(DefaultLoginPageTest.config("login", "", "/check")));
        Assertions.assertDoesNotThrow(
                () -> new DefaultLoginPage(DefaultLoginPageTest.config("/login", "/login?error=true", "/login")));
    }

    @Test
    void rejectsIndistinguishableErrorPageAndPostQueryThatQuarkusCannotMatch() {
        Assertions.assertThrows(ConfigurationException.class,
                () -> new DefaultLoginPage(DefaultLoginPageTest.config("/login", "/login", "/check")));
        Assertions.assertThrows(ConfigurationException.class,
                () -> new DefaultLoginPage(DefaultLoginPageTest.config("/login", "/error", "/check?next=true")));
    }

    private static FormAuthConfig config(String login, String error, String post) {
        return (FormAuthConfig) Proxy.newProxyInstance(DefaultLoginPageTest.class.getClassLoader(),
                new Class<?>[] { FormAuthConfig.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "loginPage" -> login.isEmpty() ? Optional.empty() : Optional.of(login);
                    case "errorPage" -> error.isEmpty() ? Optional.empty() : Optional.of(error);
                    case "postLocation" -> post;
                    case "usernameParameter" -> "j_username";
                    case "passwordParameter" -> "j_password";
                    default -> throw new UnsupportedOperationException(method.toString());
                });
    }
}
