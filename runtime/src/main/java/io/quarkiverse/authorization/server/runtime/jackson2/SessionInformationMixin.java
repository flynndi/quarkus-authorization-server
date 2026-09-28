package io.quarkiverse.authorization.server.runtime.jackson2;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
abstract class SessionInformationMixin {
    @JsonCreator
    SessionInformationMixin(@JsonProperty("principalName") String principalName,
            @JsonProperty("sessionId") String sessionId,
            @JsonProperty("authenticationTime") Instant authenticationTime) {
    }
}
