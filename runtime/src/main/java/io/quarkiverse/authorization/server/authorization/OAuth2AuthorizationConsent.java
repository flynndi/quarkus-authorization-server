package io.quarkiverse.authorization.server.authorization;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * An OAuth 2.0 consent granted to a registered client by a principal.
 */
public final class OAuth2AuthorizationConsent implements Serializable {

    @Serial
    private static final long serialVersionUID = 8762931344932176505L;

    private static final String AUTHORITIES_SCOPE_PREFIX = "SCOPE_";

    private final String registeredClientId;
    private final String principalName;
    private final Set<String> authorities;

    private OAuth2AuthorizationConsent(String registeredClientId, String principalName, Set<String> authorities) {
        this.registeredClientId = registeredClientId;
        this.principalName = principalName;
        this.authorities = Collections.unmodifiableSet(new HashSet<>(authorities));
    }

    public String getRegisteredClientId() {
        return this.registeredClientId;
    }

    public String getPrincipalName() {
        return this.principalName;
    }

    /**
     * Returns the granted authority names stored as strings in the authorization consent.
     */
    public Set<String> getAuthorities() {
        return this.authorities;
    }

    public Set<String> getScopes() {
        Set<String> scopes = new HashSet<>();
        for (String authority : this.authorities) {
            if (authority.startsWith(AUTHORITIES_SCOPE_PREFIX)) {
                scopes.add(authority.substring(AUTHORITIES_SCOPE_PREFIX.length()));
            }
        }
        return scopes;
    }

    public static Builder from(OAuth2AuthorizationConsent authorizationConsent) {
        Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
        return new Builder(
                authorizationConsent.getRegisteredClientId(),
                authorizationConsent.getPrincipalName(),
                authorizationConsent.getAuthorities());
    }

    public static Builder withId(String registeredClientId, String principalName) {
        Arguments.requireNonBlank(registeredClientId, "registeredClientId");
        Arguments.requireNonBlank(principalName, "principalName");
        return new Builder(registeredClientId, principalName);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof OAuth2AuthorizationConsent that)) {
            return false;
        }
        return this.registeredClientId.equals(that.registeredClientId)
                && this.principalName.equals(that.principalName)
                && this.authorities.equals(that.authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.registeredClientId, this.principalName, this.authorities);
    }

    public static final class Builder implements Serializable {

        @Serial
        private static final long serialVersionUID = 2270714878225323025L;

        private final String registeredClientId;
        private final String principalName;
        private final Set<String> authorities = new HashSet<>();

        private Builder(String registeredClientId, String principalName) {
            this(registeredClientId, principalName, Set.of());
        }

        private Builder(String registeredClientId, String principalName, Set<String> authorities) {
            this.registeredClientId = registeredClientId;
            this.principalName = principalName;
            this.authorities.addAll(authorities);
        }

        public Builder scope(String scope) {
            Arguments.requireNonBlank(scope, "scope");
            return authority(AUTHORITIES_SCOPE_PREFIX + scope);
        }

        public Builder authority(String authority) {
            Arguments.requireNonBlank(authority, "authority");
            this.authorities.add(authority);
            return this;
        }

        public Builder authorities(Consumer<Set<String>> authoritiesConsumer) {
            Objects.requireNonNull(authoritiesConsumer, "authoritiesConsumer cannot be null")
                    .accept(this.authorities);
            return this;
        }

        public OAuth2AuthorizationConsent build() {
            if (this.authorities.isEmpty()) {
                throw new IllegalArgumentException("authorities cannot be empty");
            }
            return new OAuth2AuthorizationConsent(this.registeredClientId, this.principalName, this.authorities);
        }
    }
}
