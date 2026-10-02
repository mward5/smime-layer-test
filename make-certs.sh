#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Throwaway CA, sender and recipient certificates, and an NSS database that
# trusts the CA and holds the recipient's private key (to decrypt).
set -euo pipefail
cd "$(dirname "$0")"
rm -rf certs nssdb && mkdir certs nssdb
cd certs

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=Layer Test CA" \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
	-keyout ca.key -out ca.crt 2>/dev/null

for who in sender recipient; do
	openssl req -newkey rsa:2048 -nodes -subj "/CN=Test ${who^}/emailAddress=${who}@example.test" \
		-keyout $who.key -out $who.csr 2>/dev/null
	openssl x509 -req -in $who.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
		-extfile <(printf 'subjectAltName=email:%s@example.test\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\n' $who) \
		-out $who.crt 2>/dev/null
	openssl pkcs12 -export -passout pass: -name "$who" -inkey $who.key -in $who.crt -certfile ca.crt -out $who.p12
done

cd ..
certutil -N -d sql:nssdb --empty-password
certutil -A -d sql:nssdb -n "Layer Test CA" -t "CT,C,C" -i certs/ca.crt
pk12util -i certs/recipient.p12 -d sql:nssdb -W "" -K "" >/dev/null
certutil -A -d sql:nssdb -n sender -t ",," -i certs/sender.crt
certutil -L -d sql:nssdb
