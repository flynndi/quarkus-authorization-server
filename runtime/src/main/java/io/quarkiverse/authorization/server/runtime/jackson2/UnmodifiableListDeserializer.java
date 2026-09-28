/*
 * Copyright 2004-present the original author or authors.
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

final class UnmodifiableListDeserializer extends JsonDeserializer<List<?>> {

    @Override
    public List<?> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper objectMapper = (ObjectMapper) parser.getCodec();
        JsonNode node = objectMapper.readTree(parser);
        List<Object> result = new ArrayList<>();
        if (node instanceof ArrayNode arrayNode) {
            for (JsonNode elementNode : arrayNode) {
                result.add(objectMapper.readValue(elementNode.traverse(objectMapper), Object.class));
            }
        } else if (node != null) {
            result.add(objectMapper.readValue(node.traverse(objectMapper), Object.class));
        }
        return Collections.unmodifiableList(result);
    }
}
