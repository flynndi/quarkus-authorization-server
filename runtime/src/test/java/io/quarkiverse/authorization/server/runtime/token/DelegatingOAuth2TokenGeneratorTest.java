package io.quarkiverse.authorization.server.runtime.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;

class DelegatingOAuth2TokenGeneratorTest {

    private static final OAuth2TokenContext CONTEXT = DefaultOAuth2TokenContext.builder().build();

    @Test
    void returnsFirstGeneratedTokenAndStopsDelegating() {
        AtomicInteger laterGeneratorInvocations = new AtomicInteger();
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-token", Instant.now(), Instant.now().plusSeconds(3600));
        DelegatingOAuth2TokenGenerator generator = new DelegatingOAuth2TokenGenerator(
                context -> null,
                context -> refreshToken,
                context -> {
                    laterGeneratorInvocations.incrementAndGet();
                    return null;
                });

        assertSame(refreshToken, generator.generate(CONTEXT));
        assertEquals(0, laterGeneratorInvocations.get());
    }

    @Test
    void returnsNullWhenNoGeneratorSupportsContext() {
        DelegatingOAuth2TokenGenerator generator = new DelegatingOAuth2TokenGenerator(
                context -> null, context -> null);

        assertNull(generator.generate(CONTEXT));
    }

    @Test
    void requiresAtLeastOneNonNullGenerator() {
        assertThrows(IllegalArgumentException.class, DelegatingOAuth2TokenGenerator::new);
        assertThrows(IllegalArgumentException.class,
                () -> new DelegatingOAuth2TokenGenerator(context -> null, null));
    }
}
