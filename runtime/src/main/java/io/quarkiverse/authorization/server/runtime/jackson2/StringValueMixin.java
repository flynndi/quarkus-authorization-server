package io.quarkiverse.authorization.server.runtime.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

abstract class StringValueMixin {

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    StringValueMixin(String value) {
    }

    @JsonValue
    abstract String getValue();
}
