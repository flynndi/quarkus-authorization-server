package io.quarkiverse.authorization.server.runtime.jackson2;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Jackson-only binding to the Quarkus builder. Adds no state or application configuration API. */
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE, isGetterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonPOJOBuilder(withPrefix = "add")
public final class SecurityIdentityJacksonBuilder extends QuarkusSecurityIdentity.Builder {

    @Override
    @JsonProperty("principal")
    @JsonTypeInfo(use = JsonTypeInfo.Id.NONE)
    @JsonDeserialize(as = QuarkusPrincipal.class)
    @JsonSetter(nulls = Nulls.FAIL)
    public SecurityIdentityJacksonBuilder setPrincipal(Principal principal) {
        super.setPrincipal(principal);
        return this;
    }

    @Override
    @JsonProperty
    @JsonSetter(nulls = Nulls.FAIL, contentNulls = Nulls.FAIL)
    public SecurityIdentityJacksonBuilder addRoles(Set<String> roles) {
        // Polymorphic collection adapters may restore elements as Object, despite this signature.
        for (Object role : roles) {
            if (!(role instanceof String)) {
                throw new IllegalArgumentException("Persisted roles must be strings");
            }
        }
        super.addRoles(roles);
        return this;
    }

    @Override
    @JsonProperty
    @JsonSetter(nulls = Nulls.FAIL)
    public SecurityIdentityJacksonBuilder addAttributes(Map<String, Object> attributes) {
        if (!Set.of(OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE)
                .containsAll(attributes.keySet())) {
            throw new IllegalArgumentException("Unsupported persisted identity attribute");
        }
        super.addAttributes(new SecurityIdentityAttributesConverter().convert(attributes));
        return this;
    }

    @Override
    public QuarkusSecurityIdentity build() {
        QuarkusSecurityIdentity identity = super.build();
        Principal principal = identity.getPrincipal();
        if (principal == null || principal.getName() == null || principal.getName().isBlank()) {
            throw new IllegalArgumentException("Persisted identity principal cannot be empty");
        }
        return identity;
    }
}
