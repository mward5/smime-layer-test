#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""S/MIME layering test messages that decrypt and verify in your own profile.

Signing with your key and encrypting to your certificate go through NSS
(cmsutil) against your NSS database, so the private key never leaves it.
The "other signer" cases sign with the throwaway sender certificate from
make-certs.sh, whose CA is not trusted in your database unless you import it.

Each message is encrypted to your certificate and to any further
certificates named on the command line, so others can open them too.

Usage: make-own-key-messages.py --nickname NICK --address ADDR [--name NAME]
                                [--nssdb DIR] [extra-recipient.crt...]
  writes own-key-messages/*.eml; certutil -L -d sql:DIR lists the nicknames
"""
import argparse
import base64
import os
import subprocess
import sys
import tempfile
import uuid
from email.utils import formatdate

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "own-key-messages")
CRLF = "\r\n"

# Set from the command line in main()
NSSDB = MY_NICK = MY_ADDR = MY_NAME = None
EXTRA_RECIPIENTS = []


def cmsutil(*args, data):
	with tempfile.TemporaryDirectory() as tmp:
		src, dst = os.path.join(tmp, "in"), os.path.join(tmp, "out")
		with open(src, "wb") as f:
			f.write(data)
		subprocess.run(["cmsutil", *args, "-d", NSSDB, "-i", src, "-o", dst], check=True, stdin=subprocess.DEVNULL)
		with open(dst, "rb") as f:
			return f.read()


def b64(data):
	return base64.encodebytes(data).decode().replace("\n", CRLF)


def entity(headers, body):
	return CRLF.join(headers) + CRLF + CRLF + body


def sign_mine(content):
	return cmsutil("-S", "-T", "-G", "-H", "SHA256", "-N", MY_NICK, data=content.encode())


def sign_other(content):
	certs = os.path.join(HERE, "certs")
	with tempfile.TemporaryDirectory() as tmp:
		src = os.path.join(tmp, "in")
		with open(src, "wb") as f:
			f.write(content.encode())
		return subprocess.run(["openssl", "cms", "-sign", "-binary", "-outform", "DER", "-md", "sha256",
			"-signer", os.path.join(certs, "sender.crt"), "-inkey", os.path.join(certs, "sender.key"),
			"-certfile", os.path.join(certs, "ca.crt"), "-in", src], check=True, capture_output=True).stdout


def sign_mine_and_other(content):
	# cmsutil signs with one certificate, so openssl adds the second signer
	certs = os.path.join(HERE, "certs")
	with tempfile.TemporaryDirectory() as tmp:
		src, mine = os.path.join(tmp, "in"), os.path.join(tmp, "mine.der")
		with open(src, "wb") as f:
			f.write(content.encode())
		with open(mine, "wb") as f:
			f.write(sign_mine(content))
		return subprocess.run(["openssl", "cms", "-resign", "-binary", "-inform", "DER", "-outform", "DER", "-md", "sha256",
			"-in", mine, "-content", src, "-signer", os.path.join(certs, "sender.crt"), "-inkey", os.path.join(certs, "sender.key"),
			"-certfile", os.path.join(certs, "ca.crt")], check=True, capture_output=True).stdout


def multipart_signed(content, signature):
	boundary = "=-" + uuid.uuid4().hex
	sig_part = entity([
		'Content-Type: application/pkcs7-signature; name="smime.p7s"',
		'Content-Disposition: attachment; filename="smime.p7s"',
		"Content-Transfer-Encoding: base64"], b64(signature))
	return entity([
		f'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="{boundary}"'],
		f"--{boundary}{CRLF}{content}{CRLF}--{boundary}{CRLF}{sig_part}{CRLF}--{boundary}--{CRLF}")


def my_cert_pem():
	return subprocess.run(["certutil", "-L", "-d", NSSDB, "-n", MY_NICK, "-a"], check=True, capture_output=True, stdin=subprocess.DEVNULL).stdout


def encrypt(content):
	with tempfile.TemporaryDirectory() as tmp:
		src, mine = os.path.join(tmp, "in"), os.path.join(tmp, "mine.crt")
		with open(src, "wb") as f:
			f.write(content.encode())
		with open(mine, "wb") as f:
			f.write(my_cert_pem())
		envelope = subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", "-in", src, mine, *EXTRA_RECIPIENTS],
			check=True, capture_output=True).stdout
	return entity([
		'Content-Type: application/pkcs7-mime; name="smime.p7m"; smime-type="enveloped-data"',
		'Content-Disposition: attachment; filename="smime.p7m"',
		"Content-Transfer-Encoding: base64"], b64(envelope))


def body(text):
	return entity(["Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 7bit"], text + CRLF)


def write(name, subject, top):
	headers = [
		f'From: "{MY_NAME}" <{MY_ADDR}>' if MY_NAME else f"From: {MY_ADDR}",
		f"To: {MY_ADDR}",
		f"Subject: Layer test: {subject}",
		f"Date: {formatdate(localtime=True)}",
		f"Message-ID: <{uuid.uuid4().hex}@{MY_ADDR.split('@')[-1]}>",
		"MIME-Version: 1.0"]
	with open(os.path.join(OUT, name + ".eml"), "w", newline="") as f:
		f.write(CRLF.join(headers) + CRLF + top)
	print(f"{name}.eml  {subject}")


def tamper_outer(signed):
	# Rename the encrypted part: the signed content changes, the ciphertext does not
	return signed.replace('filename="smime.p7m"', 'filename="smime.p7x"', 1)


def main():
	global NSSDB, MY_NICK, MY_ADDR, MY_NAME, EXTRA_RECIPIENTS

	parser = argparse.ArgumentParser(description="S/MIME layering test messages made with your own key.")
	parser.add_argument("--nickname", required=True, help="NSS nickname of your signing certificate")
	parser.add_argument("--address", required=True, help="your email address, for From/To and to encrypt to")
	parser.add_argument("--name", help="display name for From")
	parser.add_argument("--nssdb", default=os.path.expanduser("~/.pki/nssdb"), help="NSS database directory (default ~/.pki/nssdb)")
	parser.add_argument("recipients", nargs="*", help="further certificates (PEM) to encrypt to")
	args = parser.parse_args()

	NSSDB = "sql:" + args.nssdb
	MY_NICK, MY_ADDR, MY_NAME = args.nickname, args.address, args.name
	EXTRA_RECIPIENTS = [os.path.abspath(p) for p in args.recipients]

	if not os.path.isdir(os.path.join(HERE, "certs")):
		subprocess.run([os.path.join(HERE, "make-certs.sh")], check=True, stdout=subprocess.DEVNULL)
	os.makedirs(OUT, exist_ok=True)

	text = "The quick brown fox jumps over the lazy dog."

	inner = body(text)
	inner_signed = multipart_signed(inner, sign_mine(inner))
	envelope = encrypt(inner_signed)

	write("1-triple-wrap-good", "triple-wrapped, both layers good, same signer",
		multipart_signed(envelope, sign_mine(envelope)))

	write("2-triple-wrap-outer-broken", "triple-wrapped, outer signature broken",
		tamper_outer(multipart_signed(envelope, sign_mine(envelope))))

	envelope_inner_broken = encrypt(inner_signed.replace("lazy dog", "lazy cat", 1))
	write("3-triple-wrap-inner-broken", "triple-wrapped, inner signature broken",
		multipart_signed(envelope_inner_broken, sign_mine(envelope_inner_broken)))

	write("4-triple-wrap-other-outer-signer", "triple-wrapped, outer signed by a different certificate",
		multipart_signed(envelope, sign_other(envelope)))

	inner_signed_two = multipart_signed(inner, sign_mine_and_other(inner))
	envelope_two = encrypt(inner_signed_two)
	write("7-triple-wrap-inner-two-signers", "triple-wrapped, inner signed by two, outer by one of them",
		multipart_signed(envelope_two, sign_mine(envelope_two)))

	write("8-triple-wrap-outer-two-signers", "triple-wrapped, inner signed by one, outer by two",
		multipart_signed(envelope, sign_mine_and_other(envelope)))

	envelope_plain = encrypt(body(text))
	write("5-encrypt-then-sign", "encrypted then signed, no inner signature",
		multipart_signed(envelope_plain, sign_mine(envelope_plain)))

	write("6-encrypt-then-sign-broken", "encrypted then signed, signature broken",
		tamper_outer(multipart_signed(envelope_plain, sign_mine(envelope_plain))))


if __name__ == "__main__":
	main()
