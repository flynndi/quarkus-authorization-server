package io.quarkiverse.authorization.server.runtime.client.authentication;

import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.security.identity.request.CertificateAuthenticationRequest;

/** A TLS peer certificate plus the OAuth client identifier; no authentication method is assumed. */
public final class X509ClientCertificateAuthenticationRequest extends CertificateAuthenticationRequest {
    private final String clientId;

    public X509ClientCertificateAuthenticationRequest(String clientId, CertificateCredential certificate) {
        super(certificate);
        this.clientId = Arguments.requireNonBlank(clientId, "clientId");
    }

    public String getClientId() {
        return this.clientId;
    }
}
