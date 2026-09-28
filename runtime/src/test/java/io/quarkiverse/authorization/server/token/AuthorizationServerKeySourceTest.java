package io.quarkiverse.authorization.server.token;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource.Key;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource.KeySet;
import io.smallrye.jwt.util.KeyUtils;

class AuthorizationServerKeySourceTest {
    static KeyPair rsa;
    static KeyPair other;

    @BeforeAll
    static void keys() throws Exception {
        rsa = KeyUtils.generateKeyPair(2048);
        other = KeyUtils.generateKeyPair(2048);
    }

    static Key key(String id) {
        return new Key(id, SignatureAlgorithm.RS256, rsa.getPrivate(), rsa.getPublic());
    }

    static AuthorizationServerKeyManager manager(List<Key> keys, String active) {
        return new AuthorizationServerKeyManager(() -> new KeySet(keys, active));
    }

    @Test
    void selectsSigningKeyAndPublishesOnlyPublicMaterial() {
        var manager = manager(
                List.of(
                        key("active"),
                        new Key("old", SignatureAlgorithm.RS256, null, other.getPublic())),
                "active");
        assertEquals("active", manager.getKeyId());
        assertSame(rsa.getPrivate(), manager.getPrivateKey());
        assertEquals(2, manager.getPublicJwks().size());
        assertTrue(manager.getPublicJwks().stream().allMatch(jwk -> !jwk.containsKey("d")));
    }

    @Test
    void encodesRsaJwkIntegersWithoutTheSignByte() {
        var jwk = manager(List.of(key("rsa")), "rsa").getPublicJwks().getFirst();
        var publicKey = (RSAPublicKey) rsa.getPublic();
        byte[] modulus = Base64.getUrlDecoder().decode((String) jwk.get("n"));
        byte[] exponent = Base64.getUrlDecoder().decode((String) jwk.get("e"));

        assertEquals(256, modulus.length);
        assertEquals(publicKey.getModulus(), new BigInteger(1, modulus));
        assertEquals(publicKey.getPublicExponent(), new BigInteger(1, exponent));
        assertFalse(((String) jwk.get("n")).contains("="));
    }

    @ParameterizedTest
    @CsvSource({ "ES256,secp256r1,32", "ES384,secp384r1,48", "ES512,secp521r1,66" })
    void preservesEcJwkCoordinateWidths(SignatureAlgorithm algorithm, String curve, int coordinateSize) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curve));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        var publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(spec.getGenerator(), spec));
        var manager = manager(List.of(key("rsa"), new Key("ec", algorithm, null, publicKey)), "rsa");
        var jwk = manager.getPublicJwks().stream().filter(value -> "ec".equals(value.get("kid"))).findFirst().orElseThrow();
        byte[] x = Base64.getUrlDecoder().decode((String) jwk.get("x"));
        byte[] y = Base64.getUrlDecoder().decode((String) jwk.get("y"));

        assertEquals(coordinateSize, x.length);
        assertEquals(coordinateSize, y.length);
        assertEquals(spec.getGenerator().getAffineX(), new BigInteger(1, x));
        assertEquals(spec.getGenerator().getAffineY(), new BigInteger(1, y));
        assertFalse(jwk.containsKey("d"));
        // P-521's generator X needs a leading zero byte to occupy the required 66-byte coordinate.
        if (algorithm == SignatureAlgorithm.ES512) {
            assertEquals(0, x[0]);
        }
    }

    @Test
    void rejectsDuplicateKeyIds() {
        assertTrue(
                assertThrows(
                        IllegalStateException.class,
                        () -> manager(List.of(key("same"), key("same")), "same"))
                        .getMessage()
                        .contains("Duplicate"));
    }

    @Test
    void rejectsUnknownOrUnspecifiedActiveKey() {
        assertThrows(IllegalStateException.class, () -> manager(List.of(key("a")), "missing"));
        assertThrows(IllegalStateException.class, () -> manager(List.of(key("a"), key("b")), null));
    }

    @Test
    void rejectsAnActiveVerificationOnlyKey() {
        assertThrows(
                IllegalStateException.class,
                () -> manager(
                        List.of(
                                new Key(
                                        "old",
                                        SignatureAlgorithm.RS256,
                                        null,
                                        rsa.getPublic())),
                        null));
    }

    @Test
    void validatesApplicationKeyPairsAndAlgorithms() {
        assertThrows(
                IllegalStateException.class,
                () -> manager(
                        List.of(
                                new Key(
                                        "bad",
                                        SignatureAlgorithm.RS256,
                                        rsa.getPrivate(),
                                        other.getPublic())),
                        null));
        assertThrows(
                IllegalStateException.class,
                () -> manager(
                        List.of(
                                new Key(
                                        "bad",
                                        SignatureAlgorithm.ES256,
                                        rsa.getPrivate(),
                                        rsa.getPublic())),
                        null));
    }

    @Test
    void rejectsEmptyOrNullSources() {
        assertThrows(IllegalStateException.class, () -> manager(List.of(), null));
        assertThrows(
                NullPointerException.class, () -> new AuthorizationServerKeyManager(() -> null));
    }

    @Test
    void keySetTakesAnImmutableSnapshot() {
        var input = new ArrayList<>(List.of(key("a")));
        var keys = new KeySet(input, null);
        input.clear();
        assertEquals(1, keys.keys().size());
        assertThrows(UnsupportedOperationException.class, () -> keys.keys().clear());
    }
}
