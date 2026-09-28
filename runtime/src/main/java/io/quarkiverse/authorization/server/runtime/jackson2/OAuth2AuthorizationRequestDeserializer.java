/*
 * Copyright 2020-2022 the original author or authors.
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
package io.quarkiverse.authorization.server.runtime.jackson2;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest.Builder;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;

final class OAuth2AuthorizationRequestDeserializer extends JsonDeserializer<OAuth2AuthorizationRequest> {

    @Override
    public OAuth2AuthorizationRequest deserialize(JsonParser parser, DeserializationContext context)
            throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);
        AuthorizationGrantType authorizationGrantType = convertAuthorizationGrantType(
                root.findValue("authorizationGrantType"));
        Builder builder = getBuilder(parser, authorizationGrantType);
        builder.authorizationUri(JsonNodeUtils.findStringValue(root, "authorizationUri"));
        builder.clientId(JsonNodeUtils.findStringValue(root, "clientId"));
        builder.redirectUri(JsonNodeUtils.findStringValue(root, "redirectUri"));
        builder.scopes(JsonNodeUtils.findValue(root, "scopes", JsonNodeUtils.STRING_SET, mapper));
        builder.state(JsonNodeUtils.findStringValue(root, "state"));
        builder.additionalParameters(
                JsonNodeUtils.findValue(root, "additionalParameters", JsonNodeUtils.STRING_OBJECT_MAP, mapper));
        builder.authorizationRequestUri(JsonNodeUtils.findStringValue(root, "authorizationRequestUri"));
        builder.attributes(JsonNodeUtils.findValue(root, "attributes", JsonNodeUtils.STRING_OBJECT_MAP, mapper));
        return builder.build();
    }

    private static Builder getBuilder(JsonParser parser, AuthorizationGrantType authorizationGrantType)
            throws JsonParseException {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
            return OAuth2AuthorizationRequest.authorizationCode();
        }
        throw new JsonParseException(parser, "Invalid authorizationGrantType");
    }

    private static AuthorizationGrantType convertAuthorizationGrantType(JsonNode jsonNode) {
        String value = jsonNode != null && jsonNode.isTextual()
                ? jsonNode.asText()
                : JsonNodeUtils.findStringValue(jsonNode, "value");
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equalsIgnoreCase(value)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        }
        return null;
    }
}
