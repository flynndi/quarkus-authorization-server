#!/usr/bin/env bash
# Public test keys only. Run from any directory with OpenSSL and JDK keytool installed.
set -euo pipefail
cd "$(dirname "$0")"
fixture_tmp=$(mktemp -d)
trap 'rm -rf "$fixture_tmp"' EXIT
openssl req -new -newkey rsa:2048 -nodes -x509 -days 3650 -subj '/CN=OAuth Test CA' -keyout "$fixture_tmp/ca.key" -out ca.pem
for fixture_name in server ca-client wrong-client; do
  fixture_dn=$fixture_name
  if [ "$fixture_name" = server ]; then fixture_dn=localhost; fi
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$fixture_dn/O=OAuth Test" -keyout "$fixture_tmp/$fixture_name.key" -out "$fixture_tmp/$fixture_name.csr"
  if [ "$fixture_name" = server ]; then
    echo 'subjectAltName=DNS:localhost,IP:127.0.0.1' > "$fixture_tmp/ext"
    echo 'extendedKeyUsage=serverAuth' >> "$fixture_tmp/ext"
  else
    echo 'extendedKeyUsage=clientAuth' > "$fixture_tmp/ext"
  fi
  openssl x509 -req -in "$fixture_tmp/$fixture_name.csr" -CA ca.pem -CAkey "$fixture_tmp/ca.key" -CAcreateserial -days 3650 -extfile "$fixture_tmp/ext" -out "$fixture_name.pem"
  openssl pkcs12 -export -name "$fixture_name" -in "$fixture_name.pem" -inkey "$fixture_tmp/$fixture_name.key" -certfile ca.pem -passout pass:password -out "$fixture_name.p12"
done
# A CA-issued leaf-only chain proves classification does not depend on the chain length.
openssl pkcs12 -export -name ca-client -in ca-client.pem -inkey "$fixture_tmp/ca-client.key" -passout pass:password -out ca-leaf-only.p12
for fixture_name in self-client self-ec untrusted; do
  if [ "$fixture_name" = self-ec ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$fixture_tmp/$fixture_name.key"
  else
    openssl genrsa -out "$fixture_tmp/$fixture_name.key" 2048
  fi
  openssl req -new -x509 -key "$fixture_tmp/$fixture_name.key" -days 3650 -subj "/CN=$fixture_name/O=OAuth Test" -out "$fixture_name.pem"
  openssl pkcs12 -export -name "$fixture_name" -in "$fixture_name.pem" -inkey "$fixture_tmp/$fixture_name.key" -passout pass:password -out "$fixture_name.p12"
done
keytool -genkeypair -alias expired -dname 'CN=expired' -keyalg RSA -validity 1 -startdate '2020/01/01 00:00:00' -keystore "$fixture_tmp/expired.p12" -storetype PKCS12 -storepass password
keytool -exportcert -rfc -alias expired -keystore "$fixture_tmp/expired.p12" -storepass password -file expired.pem
# A trusted self-signed certificate with the PKI client's DN must not impersonate that client.
openssl req -new -x509 -key "$fixture_tmp/self-client.key" -days 3650 -subj '/CN=ca-client/O=OAuth Test' -out self-same-dn.pem
openssl pkcs12 -export -name self-same-dn -in self-same-dn.pem -inkey "$fixture_tmp/self-client.key" -passout pass:password -out self-same-dn.p12
# Only the CA and explicitly pinned self-signed peers are trusted; never trust-all.
rm -f truststore.p12
for fixture_name in ca self-client self-ec self-same-dn; do
  keytool -importcert -noprompt -alias "$fixture_name" -file "$fixture_name.pem" -keystore truststore.p12 -storetype PKCS12 -storepass password
done
rm -f ca.srl
