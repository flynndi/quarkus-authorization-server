package io.quarkiverse.authorization.server.deployment;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;

/** Public test credentials; the application fixture publishes only certificates and public keys. */
public final class ClientCertificateTestSupport {
    private ClientCertificateTestSupport() {
    }

    public static X509Certificate certificate(String name) throws Exception {
        try (var input = ClientCertificateTestSupport.class.getResourceAsStream("/mtls/" + name + ".pem")) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }

    public static String jwks(String... names) throws Exception {
        var keys = new ArrayList<JsonWebKey>();
        for (String name : names) {
            X509Certificate certificate = ClientCertificateTestSupport.certificate(name);
            PublicJsonWebKey key = PublicJsonWebKey.Factory.newPublicJwk(certificate.getPublicKey());
            key.setCertificateChain(List.of(certificate));
            keys.add(key);
        }
        return new JsonWebKeySet(keys).toJson();
    }

    @Path("/fixture/jwks")
    public static class JwksResource {
        @GET
        @Produces("application/json")
        public String get() throws Exception {
            return ClientCertificateTestSupport.jwks("self-client", "self-ec");
        }
    }
}
