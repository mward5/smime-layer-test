# smime-layer-test

Build S/MIME test messages with different layerings — signed, encrypted,
sign-then-encrypt, encrypt-then-sign, RFC 2634 triple-wrapped, several
signers, deliberately broken signatures — and see how
[Evolution](https://gitlab.gnome.org/GNOME/evolution) parses them and what its
security bar would show, without running Evolution or touching a real profile.

It was written while reviewing
[GNOME/evolution!242](https://gitlab.gnome.org/GNOME/evolution/-/merge_requests/242)
(triple-wrapping) and found the bug fixed by
[GNOME/evolution-data-server!256](https://gitlab.gnome.org/GNOME/evolution-data-server/-/merge_requests/256)
(a signature with several signers took the result of whichever signer was
checked last).

## Requirements

- `openssl`, `python3`
- NSS tools: `certutil`, `pk12util`, `cmsutil` (Debian/Ubuntu `libnss3-tools`,
  Fedora `nss-tools`)
- A built Evolution tree (CMake build directory) and the evolution-data-server
  it was built against, with the GTK 3 development files

## Usage

```sh
./make-certs.sh       # throwaway CA, sender and recipient, and an NSS database
./make-messages.sh    # messages/*.eml
EVO_BUILD=~/src/evolution/_build ./run.sh
```

`run.sh` compiles `smime-layers.c` against the build tree and runs it on every
message (or on the ones you name). `PREFIX` points at the evolution-data-server
installation if it is not `/usr`. `HOME` is pointed at a throwaway directory
for the run, so the NSS database it opens is the test one, never yours.

For each message it prints Evolution's parts, the validity results attached to
them, and one `display` line per security bar:

```
== triple-wrap-bad-outer.eml
  part .message.signed.0.encrypted-smime.signed.button.secure_button application/vnd.evolution.secure-button
       validity SMIME|SIGNED|ENCRYPTED|VERIFIED  sign=GOOD encrypt=encrypted  signer=sender@example.test
       validity SMIME|SIGNED|VERIFIED|OUTER  sign=BAD encrypt=none  signer=sender@example.test
       display  red    details=split  "Invalid signature (Test Sender <sender@example.test>) Encrypted"
```

`details=split` means the expanded details list the outer and inner signature
separately. `./run.sh --html` also prints the bar's HTML.

## The messages

| Message | Layering |
|---|---|
| `sign-only` | signed |
| `encrypt-only` | encrypted |
| `sign-encrypt` | signed, then encrypted |
| `encrypt-sign` | encrypted, then signed |
| `encrypt-sign-bad` | the same, signature broken |
| `triple-wrap` | signed, encrypted, signed (RFC 2634) |
| `triple-wrap-bad-outer` | triple-wrapped, outer signature broken, inner good |
| `inner-two-outer-one` | triple-wrapped, inner signed by two, outer by one of them |
| `inner-one-outer-two` | triple-wrapped, inner signed by one, outer by two |
| `two-signers` | signed by two |
| `two-signers-first-broken` | signed by two, first signature value corrupted |

The broken outer signatures rename the encrypted part's filename after
signing: the signed content changes, the ciphertext does not, so decryption
and the inner signature still succeed. `two-signers-first-broken` flips a byte
in one signer's signature value, so the content and the other signature are
intact.

## Messages for a real profile

`make-own-key-messages.py` builds a similar set that opens in your own Evolution:
signed with your key, encrypted to your certificate, and optionally to other
people's so you can send them the set.

```sh
certutil -L -d sql:$HOME/.pki/nssdb          # find your certificate's nickname
./make-own-key-messages.py --nickname "My Cert" --address me@example.org \
    --name "My Name" [colleague.crt ...]
```

Signing goes through `cmsutil` against your NSS database, so the private key is
used in place and never exported. Encryption needs only public certificates.
The messages land in `own-key-messages/`.

The cases that need a second signer use the throwaway `Test Sender`
certificate. Its CA is not trusted in your database, so those signatures show
as "cannot verify sender". To see them as valid, trust `certs/ca.crt` for
email, but only in a test profile, or remove it afterwards: its key is a
throwaway sitting in `certs/`.

## Licence

MIT. See `LICENSE`.
