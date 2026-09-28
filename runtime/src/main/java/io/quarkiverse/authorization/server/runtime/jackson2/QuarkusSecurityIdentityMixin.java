package io.quarkiverse.authorization.server.runtime.jackson2;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * The JDBC identity contract. Runtime credentials and permission methods are not JSON properties.
 */
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE, isGetterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonDeserialize(builder = SecurityIdentityJacksonBuilder.class)
abstract class QuarkusSecurityIdentityMixin {

    @JsonProperty
    @JsonTypeInfo(use = JsonTypeInfo.Id.NONE)
    @JsonSerialize(as = Principal.class)
    abstract Principal getPrincipal();

    @JsonProperty
    abstract Set<String> getRoles();

    @JsonProperty
    @JsonSerialize(converter = SecurityIdentityAttributesConverter.class)
    abstract Map<String, Object> getAttributes();
}
