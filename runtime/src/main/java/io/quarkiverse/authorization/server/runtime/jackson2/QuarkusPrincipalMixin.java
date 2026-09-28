package io.quarkiverse.authorization.server.runtime.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Persist a Principal as its name, independently of its runtime implementation. */
abstract class QuarkusPrincipalMixin {

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    QuarkusPrincipalMixin(String name) {
    }

    @JsonValue
    abstract String getName();
}
