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
package io.quarkiverse.authorization.server.authorization;

/**
 * The names of the claims defined for an OAuth 2.0 Token Introspection Response.
 */
public final class OAuth2TokenIntrospectionClaimNames {

    public static final String ACTIVE = "active";
    public static final String USERNAME = "username";
    public static final String CLIENT_ID = "client_id";
    public static final String SCOPE = "scope";
    public static final String TOKEN_TYPE = "token_type";
    public static final String EXP = "exp";
    public static final String IAT = "iat";
    public static final String NBF = "nbf";
    public static final String SUB = "sub";
    public static final String AUD = "aud";
    public static final String ISS = "iss";
    public static final String JTI = "jti";

    private OAuth2TokenIntrospectionClaimNames() {
    }
}
