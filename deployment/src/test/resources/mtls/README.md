# OAuth client TLS fixtures

All keys and passwords here are public test data. They are test resources only and must never be used by a deployed server.

Run `bash generate.sh` to recreate the fixtures with OpenSSL and JDK keytool. The script removes only its temporary private-key/CSR directory and replaces these generated test stores. Password: `password`.

- `server`: localhost server certificate signed by the test CA, with DNS/IP SAN.
- `ca-client`, `wrong-client`: CA-signed client certificates with distinct subjects.
- `ca-leaf-only`: the same client key/certificate without its CA chain; still valid PKI authentication.
- `self-client`, `self-ec`: RSA/EC self-signed clients published by the test JWKS endpoint.
- `self-same-dn`: a self-signed peer with the PKI client's DN; must not impersonate the PKI client.
- `untrusted`: a self-signed certificate absent from the server trust store; the TLS test forces its presentation.
- `expired`: a certificate valid only on 2020-01-01, for verifier expiry checks.
- `truststore`: the CA and explicitly pinned self-signed peers, excluding `untrusted`.

`X509ClientAuthenticationTest` uses HTTPS with real key/trust stores, without relaxed HTTPS validation. Its JWKS fixture uses HTTPS on localhost, with an explicit private-origin exception and the test CA configured through the Quarkus TLS registry. The runtime JWKS tests reuse copies of `server.p12` and `ca.pem` in `runtime/src/test/resources/jwks`. Native verification is deferred.
