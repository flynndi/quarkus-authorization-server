package io.quarkiverse.authorization.server.endpoint;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * A representation of an OAuth 2.0 Authorization Request.
 */
public final class OAuth2AuthorizationRequest implements Serializable {

    /** Authorization attribute containing the expiration Instant of a stored pushed authorization request. */
    public static final String PUSHED_REQUEST_EXPIRES_AT_ATTRIBUTE_NAME = "oauth2.pushed-request.expires-at";

    @Serial
    private static final long serialVersionUID = -8949741830727886963L;

    private final String authorizationUri;
    private final AuthorizationGrantType authorizationGrantType;
    private final OAuth2AuthorizationResponseType responseType;
    private final String clientId;
    private final String redirectUri;
    private final Set<String> scopes;
    private final String state;
    private final Map<String, Object> additionalParameters;
    private final String authorizationRequestUri;
    private final Map<String, Object> attributes;

    private OAuth2AuthorizationRequest(Builder builder) {
        this.authorizationUri = builder.authorizationUri;
        this.authorizationGrantType = builder.authorizationGrantType;
        this.responseType = builder.responseType;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(builder.scopes));
        this.state = builder.state;
        this.additionalParameters = Collections.unmodifiableMap(new LinkedHashMap<>(builder.additionalParameters));
        this.authorizationRequestUri = builder.authorizationRequestUri;
        this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(builder.attributes));
    }

    public String getAuthorizationUri() {
        return this.authorizationUri;
    }

    public AuthorizationGrantType getGrantType() {
        return this.authorizationGrantType;
    }

    public OAuth2AuthorizationResponseType getResponseType() {
        return this.responseType;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public String getState() {
        return this.state;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public String getAuthorizationRequestUri() {
        return this.authorizationRequestUri;
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String name) {
        return (T) this.attributes.get(name);
    }

    public static Builder authorizationCode() {
        return new Builder(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    public static Builder from(OAuth2AuthorizationRequest authorizationRequest) {
        Objects.requireNonNull(authorizationRequest, "authorizationRequest cannot be null");
        return new Builder(authorizationRequest.getGrantType())
                .authorizationUri(authorizationRequest.getAuthorizationUri())
                .clientId(authorizationRequest.getClientId())
                .redirectUri(authorizationRequest.getRedirectUri())
                .scopes(authorizationRequest.getScopes())
                .state(authorizationRequest.getState())
                .additionalParameters(authorizationRequest.getAdditionalParameters())
                .attributes(authorizationRequest.getAttributes());
    }

    public static final class Builder {

        private String authorizationUri;
        private final AuthorizationGrantType authorizationGrantType;
        private final OAuth2AuthorizationResponseType responseType;
        private String clientId;
        private String redirectUri;
        private Set<String> scopes = new LinkedHashSet<>();
        private String state;
        private final Map<String, Object> additionalParameters = new LinkedHashMap<>();
        private Consumer<Map<String, Object>> parametersConsumer = parameters -> {
        };
        private final Map<String, Object> attributes = new LinkedHashMap<>();
        private String authorizationRequestUri;
        private Function<URI, URI> authorizationRequestUriFunction = Function.identity();

        private Builder(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantType = Objects.requireNonNull(
                    authorizationGrantType, "authorizationGrantType cannot be null");
            this.responseType = AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)
                    ? OAuth2AuthorizationResponseType.CODE
                    : null;
        }

        public Builder authorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String... scopes) {
            if (scopes != null && scopes.length > 0) {
                return scopes(new LinkedHashSet<>(Arrays.asList(scopes)));
            }
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes == null ? new LinkedHashSet<>() : new LinkedHashSet<>(scopes);
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            if (additionalParameters != null) {
                this.additionalParameters.putAll(additionalParameters);
            }
            return this;
        }

        public Builder additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer) {
            if (additionalParametersConsumer != null) {
                additionalParametersConsumer.accept(this.additionalParameters);
            }
            return this;
        }

        public Builder parameters(Consumer<Map<String, Object>> parametersConsumer) {
            if (parametersConsumer != null) {
                this.parametersConsumer = parametersConsumer;
            }
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            if (attributes != null) {
                this.attributes.putAll(attributes);
            }
            return this;
        }

        public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
            if (attributesConsumer != null) {
                attributesConsumer.accept(this.attributes);
            }
            return this;
        }

        public Builder authorizationRequestUri(String authorizationRequestUri) {
            this.authorizationRequestUri = authorizationRequestUri;
            return this;
        }

        /**
         * Customizes the generated authorization request URI with a standard Java URI transformation.
         */
        public Builder authorizationRequestUri(Function<URI, URI> authorizationRequestUriFunction) {
            if (authorizationRequestUriFunction != null) {
                this.authorizationRequestUriFunction = authorizationRequestUriFunction;
            }
            return this;
        }

        public OAuth2AuthorizationRequest build() {
            Arguments.requireNonBlank(this.authorizationUri, "authorizationUri");
            Arguments.requireNonBlank(this.clientId, "clientId");
            if (this.responseType == null) {
                throw new IllegalStateException("responseType cannot be null");
            }
            if (this.authorizationRequestUri == null || this.authorizationRequestUri.isBlank()) {
                this.authorizationRequestUri = buildAuthorizationRequestUri();
            }
            return new OAuth2AuthorizationRequest(this);
        }

        private String buildAuthorizationRequestUri() {
            Map<String, Object> parameters = getParameters();
            this.parametersConsumer.accept(parameters);
            String query = parameters.entrySet().stream()
                    .map(entry -> encodeQueryParameter(entry.getKey()) + "="
                            + encodeQueryParameter(String.valueOf(entry.getValue())))
                    .collect(Collectors.joining("&"));
            int fragmentIndex = this.authorizationUri.indexOf('#');
            String baseUri = fragmentIndex >= 0
                    ? this.authorizationUri.substring(0, fragmentIndex)
                    : this.authorizationUri;
            String fragment = fragmentIndex >= 0 ? this.authorizationUri.substring(fragmentIndex) : "";
            if (query.isEmpty()) {
                return this.authorizationRequestUriFunction.apply(URI.create(baseUri + fragment)).toString();
            }
            String separator = baseUri.endsWith("?") || baseUri.endsWith("&")
                    ? ""
                    : baseUri.contains("?") ? "&" : "?";
            URI generatedUri = URI.create(baseUri + separator + query + fragment);
            return this.authorizationRequestUriFunction.apply(generatedUri).toString();
        }

        private Map<String, Object> getParameters() {
            Map<String, Object> parameters = new LinkedHashMap<>();
            parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, this.responseType.getValue());
            parameters.put(OAuth2ParameterNames.CLIENT_ID, this.clientId);
            if (!this.scopes.isEmpty()) {
                parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", this.scopes));
            }
            if (this.state != null) {
                parameters.put(OAuth2ParameterNames.STATE, this.state);
            }
            if (this.redirectUri != null) {
                parameters.put(OAuth2ParameterNames.REDIRECT_URI, this.redirectUri);
            }
            parameters.putAll(this.additionalParameters);
            return parameters;
        }

        private static String encodeQueryParameter(String value) {
            return URLEncoder.encode(value, StandardCharsets.UTF_8)
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
        }
    }
}
