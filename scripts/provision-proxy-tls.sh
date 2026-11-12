#!/bin/sh
# Guest-local TLS certificate for the restricted relay. No developer signing.
set -eu
case "$(/usr/sbin/sysctl -n hw.model)" in VirtualMac*) ;; *) exit 1;; esac
proxy_tls_root=/Library/ios-worker
umask 077
cat > "$proxy_tls_root/proxy-ca.conf" <<'CONF'
[req]
prompt=no
distinguished_name=dn
x509_extensions=ca
[dn]
CN=Isolated Build Guest Package Relay
[ca]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
CONF
/usr/bin/openssl req -new -x509 -nodes -newkey rsa:2048 -days 3650 -sha256 -config "$proxy_tls_root/proxy-ca.conf" -keyout "$proxy_tls_root/proxy-ca.key" -out "$proxy_tls_root/proxy-ca.pem" 2>/dev/null
/usr/bin/openssl req -new -nodes -newkey rsa:2048 -subj '/CN=Isolated Build Package Relay' -keyout "$proxy_tls_root/proxy-leaf.key" -out "$proxy_tls_root/proxy-leaf.csr" 2>/dev/null
cat > "$proxy_tls_root/proxy-leaf.conf" <<'CONF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:registry.npmjs.org,DNS:registry.npmjs.com,DNS:bun.sh,DNS:nodejs.org,DNS:github.com,DNS:raw.githubusercontent.com,DNS:codeload.github.com,DNS:objects.githubusercontent.com,DNS:release-assets.githubusercontent.com,DNS:rubygems.org,DNS:index.rubygems.org,DNS:rubygems.global.ssl.fastly.net,DNS:cdn.cocoapods.org,DNS:trunk.cocoapods.org,DNS:storage.googleapis.com,DNS:repo.maven.apache.org,DNS:repo1.maven.org,DNS:dl.google.com,DNS:pub.dev,DNS:ghcr.io,DNS:pkg-containers.githubusercontent.com,DNS:formulae.brew.sh,DNS:api.github.com,DNS:*.supabase.co
CONF
/usr/bin/openssl x509 -req -in "$proxy_tls_root/proxy-leaf.csr" -CA "$proxy_tls_root/proxy-ca.pem" -CAkey "$proxy_tls_root/proxy-ca.key" -CAcreateserial -days 365 -sha256 -extfile "$proxy_tls_root/proxy-leaf.conf" -out "$proxy_tls_root/proxy-leaf.pem" 2>/dev/null
/bin/cat /etc/ssl/cert.pem "$proxy_tls_root/proxy-ca.pem" > "$proxy_tls_root/proxy-ca-bundle.pem"
/bin/chmod 644 "$proxy_tls_root/proxy-ca.pem" "$proxy_tls_root/proxy-ca-bundle.pem" "$proxy_tls_root/proxy-leaf.pem"
/usr/bin/security delete-certificate -c 'Isolated Build Guest Package Relay' /Library/Keychains/System.keychain >/dev/null 2>&1 || true
/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$proxy_tls_root/proxy-ca.pem"
