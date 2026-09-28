/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.quarkiverse.authorization.server.runtime.token;

import java.util.List;

import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;

/**
 * Invokes token customizers in a stable order.
 */
public final class DelegatingOAuth2TokenCustomizer<T extends OAuth2TokenContext>
        implements OAuth2TokenCustomizer<T> {

    private final List<OAuth2TokenCustomizer<T>> tokenCustomizers;

    public DelegatingOAuth2TokenCustomizer(List<OAuth2TokenCustomizer<T>> tokenCustomizers) {
        if (tokenCustomizers == null || tokenCustomizers.isEmpty()) {
            throw new IllegalArgumentException("tokenCustomizers cannot be empty");
        }
        this.tokenCustomizers = List.copyOf(tokenCustomizers);
    }

    @Override
    public void customize(T context) {
        for (OAuth2TokenCustomizer<T> tokenCustomizer : this.tokenCustomizers) {
            tokenCustomizer.customize(context);
        }
    }
}
