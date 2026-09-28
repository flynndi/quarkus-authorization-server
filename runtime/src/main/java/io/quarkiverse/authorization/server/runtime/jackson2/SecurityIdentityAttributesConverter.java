package io.quarkiverse.authorization.server.runtime.jackson2;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.util.StdConverter;

import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;

/**
 * JDBC Jackson adapter selecting protocol attributes; arbitrary request attributes stay in memory.
 */
public final class SecurityIdentityAttributesConverter
        extends StdConverter<Map<String, Object>, Map<String, Object>> {

    @Override
    public Map<String, Object> convert(Map<String, Object> attributes) {
        List<Map<String, Object>> actors = OAuth2TokenExchangeTokenCustomizers.getActors(attributes);
        return actors.isEmpty()
                ? Map.of()
                : Map.of(OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE, actors);
    }
}
