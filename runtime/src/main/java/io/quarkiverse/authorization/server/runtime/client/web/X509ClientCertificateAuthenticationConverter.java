package io.quarkiverse.authorization.server.runtime.client.web;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateAuthenticationRequest;
import io.quarkiverse.authorization.server.runtime.web.authentication.AuthenticationConverter;
import io.quarkus.security.credential.CertificateCredential;
import io.vertx.ext.web.RoutingContext;

/** Reads only the actual TLS session, using the same transport API as Quarkus mTLS authentication. */
@Singleton
public final class X509ClientCertificateAuthenticationConverter
        implements AuthenticationConverter<X509ClientCertificateAuthenticationRequest> {
    @Override
    public X509ClientCertificateAuthenticationRequest convert(RoutingContext context) {
        if (!context.request().isSSL())
            return null;
        Certificate[] certificates;
        try {
            certificates = context.request().sslSession().getPeerCertificates();
        } catch (SSLPeerUnverifiedException exception) {
            return null;
        }
        if (certificates.length == 0 || !(certificates[0] instanceof X509Certificate certificate))
            return null;
        var clientIds = context.request().formAttributes().getAll(OAuth2ParameterNames.CLIENT_ID);
        if (clientIds.size() != 1 || clientIds.getFirst().isBlank()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return new X509ClientCertificateAuthenticationRequest(clientIds.getFirst(), new CertificateCredential(certificate));
    }
}
