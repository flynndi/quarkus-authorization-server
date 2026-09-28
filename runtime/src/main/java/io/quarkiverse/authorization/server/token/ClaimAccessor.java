package io.quarkiverse.authorization.server.token;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Exposes the claims associated with a token.
 */
public interface ClaimAccessor {

    Map<String, Object> getClaims();

    @SuppressWarnings("unchecked")
    default <T> T getClaim(String claim) {
        return (T) getClaims().get(claim);
    }

    default boolean hasClaim(String claim) {
        return getClaims().containsKey(claim);
    }

    default String getClaimAsString(String claim) {
        Object value = getClaim(claim);
        return value != null ? value.toString() : null;
    }

    default URL getClaimAsURL(String claim) {
        Object value = getClaim(claim);
        if (value == null) {
            return null;
        }
        if (value instanceof URL url) {
            return url;
        }
        try {
            return new URI(value.toString()).toURL();
        } catch (Exception exception) {
            throw new IllegalArgumentException("Claim '" + claim + "' must be a valid URL", exception);
        }
    }

    @SuppressWarnings("unchecked")
    default List<String> getClaimAsStringList(String claim) {
        Object value = getClaim(claim);
        if (value == null) {
            return null;
        }
        if (!(value instanceof List<?>)) {
            throw new IllegalArgumentException("Claim '" + claim + "' must be of type List");
        }
        return (List<String>) value;
    }

    @SuppressWarnings("unchecked")
    default Map<String, Object> getClaimAsMap(String claim) {
        Object value = getClaim(claim);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("Claim '" + claim + "' must be of type Map");
        }
        return (Map<String, Object>) value;
    }

    default Boolean getClaimAsBoolean(String claim) {
        Object value = getClaim(claim);
        if (value == null || value instanceof Boolean) {
            return (Boolean) value;
        }
        if ("true".equalsIgnoreCase(value.toString())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.toString())) {
            return false;
        }
        throw new IllegalArgumentException("Claim '" + claim + "' must be of type Boolean");
    }

    default Instant getClaimAsInstant(String claim) {
        Object value = getClaim(claim);
        if (value == null || value instanceof Instant) {
            return (Instant) value;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        return Instant.parse(value.toString());
    }
}
