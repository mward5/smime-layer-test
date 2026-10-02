#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# S/MIME test messages with different layerings, built with openssl and the
# throwaway certificates from make-certs.sh.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf messages work && mkdir messages work

SENDER="-signer certs/sender.crt -inkey certs/sender.key"
RECIPIENT="-signer certs/recipient.crt -inkey certs/recipient.key"

sign () {	# clear-signed multipart/signed, as a MIME entity (no MIME-Version); extra args add signers
	local in=$1 out=$2; shift 2
	# shellcheck disable=SC2086
	openssl smime -sign -md sha256 $SENDER "$@" -in "$in" | sed '/^MIME-Version:/d' > "$out"
}
encrypt () {	# application/pkcs7-mime enveloped-data, as a MIME entity
	openssl smime -encrypt -aes256 -in "$1" certs/recipient.crt | sed '/^MIME-Version:/d' > "$2"
}
message () {	# prepend RFC 822 headers to an entity
	{ printf 'From: Test Sender <sender@example.test>\nTo: Test Recipient <recipient@example.test>\nSubject: %s\nDate: Thu, 25 Sep 2026 12:00:00 +0000\nMessage-ID: <%s@example.test>\nMIME-Version: 1.0\n' "$2" "$1"
	  cat "$3"; } > "messages/$1.eml"
}

printf 'Content-Type: text/plain; charset=utf-8\n\nThe quick brown fox jumps over the lazy dog.\n' > work/body

sign work/body work/s;                                   message sign-only           "Signed only"                 work/s
encrypt work/body work/e;                                message encrypt-only        "Encrypted only"              work/e
encrypt work/s work/se;                                  message sign-encrypt        "Signed then encrypted"       work/se
sign work/e work/es;                                     message encrypt-sign        "Encrypted then signed"       work/es
sign work/se work/ses;                                   message triple-wrap         "Triple-wrapped"              work/ses

# Break only the outer signature: rename the encrypted part inside the signed
# content. The ciphertext is untouched, so decryption and the inner signature
# still succeed.
sed '0,/filename="smime.p7m"/s//filename="smime.p7x"/' work/ses > work/ses-bad
message triple-wrap-bad-outer "Triple-wrapped, outer signature broken" work/ses-bad
sed '0,/filename="smime.p7m"/s//filename="smime.p7x"/' work/es > work/es-bad
message encrypt-sign-bad       "Encrypted then signed, signature broken" work/es-bad

# Two signers on one layer
# shellcheck disable=SC2086
sign work/body work/s2 $RECIPIENT
encrypt work/s2 work/s2e
sign work/s2e work/s2es;                                 message inner-two-outer-one "Triple-wrapped, inner signed by two, outer by one of them" work/s2es
# shellcheck disable=SC2086
sign work/se work/ses2 $RECIPIENT;                       message inner-one-outer-two "Triple-wrapped, inner signed by one, outer by two"        work/ses2
message two-signers                                      "Signed by two"               work/s2

# Two signers, the first signature value corrupted: the content is intact and
# the other signature verifies, so only one signer fails.
python3 - work/s2 work/s2-bad <<'EOF'
import base64, re, subprocess, sys
text = open(sys.argv[1]).read()
boundary = re.search(r'boundary="([^"]+)"', text).group(1)
sig_part = text.split("--" + boundary)[2]
headers, b64 = sig_part.split("\n\n", 1)
der = bytearray(base64.b64decode(b64))
asn = subprocess.run(["openssl", "asn1parse", "-inform", "DER"], input=bytes(der), capture_output=True, check=True).stdout.decode()
first = next(l for l in asn.splitlines() if "OCTET STRING" in l and "l= 256" in l)
offset, header_len = int(first.split(":")[0]), int(first.split("hl=")[1].split()[0])
der[offset + header_len + 100] ^= 0xff
encoded = base64.encodebytes(bytes(der)).decode()
open(sys.argv[2], "w").write(text.replace(sig_part, headers + "\n\n" + encoded + "\n"))
EOF
message two-signers-first-broken                         "Signed by two, first signature broken" work/s2-bad

ls messages
