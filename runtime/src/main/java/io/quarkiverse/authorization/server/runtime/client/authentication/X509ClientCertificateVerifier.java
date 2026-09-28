package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;

/** OAuth client matching after the host's TLS handshake has validated the peer and proof of possession. */
@Singleton
public final class X509ClientCertificateVerifier {
    private final ClientJwkSetCache keySets;

    @Inject
    public X509ClientCertificateVerifier(ClientJwkSetCache keySets) {
        this.keySets = keySets;
    }

    public ClientAuthenticationMethod verify(RegisteredClient client, X509Certificate certificate) {
        try {
            certificate.checkValidity();
            boolean selfIssued = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
            ClientAuthenticationMethod method = selfIssued
                    ? ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
                    : ClientAuthenticationMethod.TLS_CLIENT_AUTH;
            if (!client.getClientAuthenticationMethods().contains(method)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
            if (selfIssued) {
                certificate.verify(certificate.getPublicKey());
                var keys = this.keySets.get(client.getClientSettings().getJwkSetUrl());
                if (!X509ClientCertificateVerifier.matches(keys.getJsonWebKeys(), certificate)) {
                    // Allow rotation without waiting for cache expiry; jose4j throttles repeated refreshes.
                    keys.refresh();
                    if (!X509ClientCertificateVerifier.matches(keys.getJsonWebKeys(), certificate)) {
                        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
                    }
                }
            } else {
                // Compare parsed DNs, not presentation strings. A pinned self-signed peer cannot use this branch.
                X500Principal expected = new X500Principal(Arguments.requireNonBlank(
                        client.getClientSettings().getX509CertificateSubjectDN(), "x509CertificateSubjectDN"));
                if (!expected.equals(certificate.getSubjectX500Principal())) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
                }
            }
            return method;
        } catch (Exception exception) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
    }

    private static boolean matches(List<JsonWebKey> keys, X509Certificate certificate) {
        for (JsonWebKey key : keys) {
            if (key instanceof PublicJsonWebKey publicKey && publicKey.getLeafCertificate() != null
                    && Arrays.equals(certificate.getPublicKey().getEncoded(),
                            publicKey.getLeafCertificate().getPublicKey().getEncoded())) {
                return true;
            }
        }
        return false;
    }
}
