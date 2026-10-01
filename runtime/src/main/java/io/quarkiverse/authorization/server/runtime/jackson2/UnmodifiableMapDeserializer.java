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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

final class UnmodifiableMapDeserializer extends JsonDeserializer<Map<?, ?>> {

    @Override
    public Map<?, ?> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        Map<String, Object> result = new LinkedHashMap<>();
        if (parser.isExpectedStartObjectToken()) {
            parser.nextToken();
        }
        // Read values directly: an intermediate JsonNode converts decimal timestamps to doubles.
        while (parser.hasToken(JsonToken.FIELD_NAME)) {
            String name = parser.currentName();
            parser.nextToken();
            result.put(name, context.readValue(parser, Object.class));
            parser.nextToken();
        }
        if (!parser.hasToken(JsonToken.END_OBJECT)) {
            return (Map<?, ?>) context.handleUnexpectedToken(Map.class, parser);
        }
        return Collections.unmodifiableMap(result);
    }
}
