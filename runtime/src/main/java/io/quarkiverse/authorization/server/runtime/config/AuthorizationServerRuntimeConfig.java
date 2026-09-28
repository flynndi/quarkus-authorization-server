package io.quarkiverse.authorization.server.runtime.config;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/** Runtime configuration for the authorization server. */
@ConfigMapping(prefix = "quarkus.authorization-server")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface AuthorizationServerRuntimeConfig {

    Optional<String> issuer();

    /** Tenant identifier to canonical public issuer URL; used only with multiple-issuers-allowed. */
    Map<String, String> issuers();

    SigningConfig signing();

    DPoPConfig dpop();

    Map<String, RegisteredClientConfig> clients();

    /** DPoP proof validation and default replay-store limits. */
    @ConfigGroup
    interface DPoPConfig {
        @WithDefault("ES256,RS256")
        Set<SignatureAlgorithm> proofAlgorithms();

        @WithDefault("1M")
        Duration proofMaxAge();

        @WithDefault("5S")
        Duration clockSkew();

        @WithDefault("16384")
        int maxProofLength();

        @WithDefault("100000")
        int replayCacheSize();
    }

    @ConfigGroup
    interface SigningConfig {

        Optional<String> activeKeyId();

        Map<String, SigningKeyConfig> keys();

        @WithDefault("RS256")
        String algorithm();

        Optional<String> keyId();

        Optional<String> privateKeyLocation();

        Optional<String> publicKeyLocation();
    }

    @ConfigGroup
    interface SigningKeyConfig {

        @WithDefault("RS256")
        String algorithm();

        Optional<String> privateKeyLocation();

        Optional<String> publicKeyLocation();
    }

    @ConfigGroup
    interface RegisteredClientConfig {

        Optional<String> id();

        Optional<String> clientName();

        Optional<String> clientSecret();

        Optional<Instant> clientIdIssuedAt();

        Optional<Instant> clientSecretExpiresAt();

        /** Registered public JWKS URL for private_key_jwt or self_signed_tls_client_auth. */
        Optional<String> jwkSetUrl();

        /** Expected certificate subject DN for tls_client_auth. */
        Optional<String> x509CertificateSubjectDn();

        /** Required JWT assertion algorithm: RS/PS/ES for private_key_jwt, HS for client_secret_jwt. */
        Optional<String> tokenEndpointAuthenticationSigningAlgorithm();

        @WithDefault("client_secret_basic")
        Set<String> clientAuthenticationMethods();

        Set<String> authorizationGrantTypes();

        Optional<Set<String>> redirectUris();

        Optional<Set<String>> postLogoutRedirectUris();

        Optional<Set<String>> scopes();

        /** Require PKCE for authorization-code requests. */
        Optional<Boolean> requireProofKey();

        /** Require consent according to the authorization-code consent policy. */
        Optional<Boolean> requireAuthorizationConsent();

        Optional<Duration> authorizationCodeTimeToLive();

        Optional<Duration> accessTokenTimeToLive();

        Optional<OAuth2TokenFormat> accessTokenFormat();

        Optional<Duration> deviceCodeTimeToLive();

        Optional<Duration> refreshTokenTimeToLive();

        Optional<Boolean> reuseRefreshTokens();

        /** The ID Token signature algorithm; defaults to RS256 in TokenSettings. */
        Optional<SignatureAlgorithm> idTokenSignatureAlgorithm();
    }
}
