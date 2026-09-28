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
package io.quarkiverse.authorization.server.grant.clientcredentials;

import java.util.Objects;

import io.quarkiverse.authorization.server.client.RegisteredClient;

/** Validated client and grant input supplied to the application's additional validator. */
public record ClientCredentialsRequestContext(
        ClientCredentialsRequest request, RegisteredClient registeredClient) {
    public ClientCredentialsRequestContext {
        Objects.requireNonNull(request, "request cannot be null");
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
    }
}
