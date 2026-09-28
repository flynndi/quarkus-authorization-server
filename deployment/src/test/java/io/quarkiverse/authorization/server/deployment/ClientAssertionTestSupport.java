package io.quarkiverse.authorization.server.deployment;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;

/** JWT signing fixture shared by isolated client-authentication and registration applications. */
public final class ClientAssertionTestSupport {
    private ClientAssertionTestSupport() {
    }

    public static String assertion(String clientId, String secret, String audience, String kid) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(5);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        if (secret != null) {
            jws.setAlgorithmHeaderValue("HS256");
            jws.setKey(new HmacKey(secret.getBytes(StandardCharsets.UTF_8)));
        } else {
            try (var input = ClientAssertionTestSupport.class.getClassLoader().getResourceAsStream("privateKey.pem")) {
                String pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII)
                        .replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
                jws.setAlgorithmHeaderValue("RS256");
                jws.setKeyIdHeaderValue(kid);
                jws.setKey(KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem))));
            }
        }
        return jws.getCompactSerialization();
    }
}
