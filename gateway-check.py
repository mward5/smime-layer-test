#!/usr/bin/env python3
"""Check whether a signed message survives the rewrites a mail gateway makes.

Mimecast was seen rewriting two things in signed messages from Evolution,
and both broke a signature: it removed the empty line camel writes before
the first boundary of a multipart/signed, and it re-encoded quoted-printable
parts that had a literal tab in them. This applies each rewrite, and some
other plausible ones, to a saved message on its own and verifies every
signature layer again, so a fix can be judged without sending mail through
the gateway.

Rewrites:
  preamble   drop empty lines before a multipart's first boundary (Mimecast)
  qp-tab     re-encode quoted-printable parts holding a literal tab (Mimecast)
  trailing   strip trailing spaces and tabs from every body line
  unfold     unfold folded headers of the body parts
  from       mbox-quote "From " at the start of a line as ">From "
  epilogue   add an empty line after each closing boundary

S/MIME layers are checked with openssl, without checking the certificate
chain; OpenPGP layers with gpg against the local keyring. Encrypted layers
are not opened.

Usage:
    ./gateway-check.py MESSAGE...
"""

import os
import re
import subprocess
import sys
import tempfile
from email import message_from_bytes
from email.policy import compat32


def load(path):
    """Read a message as LF-terminated bytes, without an mbox "From " line."""
    with open(path, "rb") as handle:
        data = handle.read().replace(b"\r\n", b"\n")
    if data.startswith(b"From "):
        data = data[data.index(b"\n") + 1:]
    return data


def split_entity(data):
    """Split an entity into its header block and its body."""
    if data.startswith(b"\n"):
        return b"", data[1:]
    end = data.find(b"\n\n")
    if end == -1:
        return data, b""
    return data[:end], data[end + 2:]


def headers_of(head):
    return message_from_bytes(head + b"\n\n", policy=compat32)


def parts_of(body, boundary):
    """Return (start, end) of each part of a multipart body, and the offset
    where its first delimiter line starts."""
    delim = b"--" + boundary
    pattern = re.compile(b"(?:^|\n)" + re.escape(delim) + b"(--)?[ \t]*(?=\n|$)")
    spans, first, start = [], None, None
    for match in pattern.finditer(body):
        if first is None:
            first = match.start() + (body[match.start():match.start() + 1] == b"\n")
        if start is not None:
            spans.append((start, match.start()))
        if match.group(1):
            break
        start = match.end() + 1
    return spans, first


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, **kwargs)


def verify_cms(signature, content, tmp):
    sig = os.path.join(tmp, "sig.der")
    with open(sig, "wb") as handle:
        handle.write(signature)
    args = ["openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", sig,
            "-binary", "-out", os.path.join(tmp, "out")]
    if content is not None:
        dat = os.path.join(tmp, "content")
        with open(dat, "wb") as handle:
            handle.write(content)
        args += ["-content", dat]
    result = run(args)
    if result.returncode == 0:
        return "good"
    return "BAD" if b"verification failure" in result.stderr else "error"


def verify_pgp(signature, content, tmp):
    sig, dat = os.path.join(tmp, "sig.asc"), os.path.join(tmp, "content")
    with open(sig, "wb") as handle:
        handle.write(signature)
    with open(dat, "wb") as handle:
        handle.write(content)
    status = run(["gpg", "--batch", "--status-fd", "1", "--verify", sig, dat]).stdout
    if b"[GNUPG:] GOODSIG" in status:
        return "good"
    if b"[GNUPG:] BADSIG" in status:
        return "BAD"
    return "no key" if b"NO_PUBKEY" in status else "error"


def decode_body(msg, body):
    if (msg.get("Content-Transfer-Encoding") or "").strip().lower() == "base64":
        import base64
        return base64.b64decode(body)
    return body


def check(data, tmp, path="1"):
    """Verify every signature layer of an entity; return [(path, kind, result)]."""
    head, body = split_entity(data)
    msg = headers_of(head)
    ctype = msg.get_content_type()
    results = []

    if ctype.startswith("multipart/"):
        boundary = msg.get_param("boundary")
        if not boundary:
            return results
        spans, _ = parts_of(body, boundary.encode())
        if ctype == "multipart/signed" and len(spans) >= 2:
            content = body[spans[0][0]:spans[0][1]].replace(b"\n", b"\r\n")
            sig_head, sig_body = split_entity(body[spans[1][0]:spans[1][1]])
            protocol = (msg.get_param("protocol") or "").lower()
            signature = decode_body(headers_of(sig_head), sig_body)
            if "pkcs7" in protocol:
                results.append((path, "S/MIME", verify_cms(signature, content, tmp)))
            elif "pgp" in protocol:
                results.append((path, "OpenPGP", verify_pgp(signature, content, tmp)))
        for index, (start, end) in enumerate(spans, 1):
            results += check(body[start:end], tmp, f"{path}.{index}")
    elif ctype in ("application/pkcs7-mime", "application/x-pkcs7-mime"):
        if (msg.get_param("smime-type") or "").lower() == "signed-data":
            result = verify_cms(decode_body(msg, body), None, tmp)
            results.append((path, "S/MIME opaque", result))
            if result == "good":
                with open(os.path.join(tmp, "out"), "rb") as handle:
                    inner = handle.read().replace(b"\r\n", b"\n")
                results += check(inner, tmp, f"{path}.1")
        else:
            results.append((path, "encrypted", "not opened"))
    elif ctype == "message/rfc822":
        results += check(body, tmp, f"{path}.1")
    return results


def entities(data):
    """Yield (head, body_start, body) for every entity, depth first."""
    stack = [(0, len(data))]
    while stack:
        offset, end = stack.pop()
        head, body = split_entity(data[offset:end])
        body_start = end - len(body)
        yield head, body_start, body
        msg = headers_of(head)
        if msg.get_content_type().startswith("multipart/") and msg.get_param("boundary"):
            spans, _ = parts_of(body, msg.get_param("boundary").encode())
            stack += [(body_start + s, body_start + e) for s, e in reversed(spans)]
        elif msg.get_content_type() == "message/rfc822":
            stack.append((body_start, end))


def edit_entities(data, edit):
    """Apply edit(head, body_start, body) -> [(start, end, new)] to all entities."""
    edits = []
    for head, body_start, body in entities(data):
        edits += edit(head, body_start, body)
    for start, end, new in sorted(edits, reverse=True):
        data = data[:start] + new + data[end:]
    return data


def rewrite_preamble(data):
    def edit(head, body_start, body):
        msg = headers_of(head)
        if not msg.get_content_type().startswith("multipart/") or not msg.get_param("boundary"):
            return []
        _, first = parts_of(body, msg.get_param("boundary").encode())
        if first and not body[:first].strip(b"\n"):
            return [(body_start, body_start + first, b"")]
        return []
    return edit_entities(data, edit)


QP_SAFE = set(range(33, 61)) | set(range(62, 127)) | {32}


def qp_encode(data):
    """camel's quoted-printable encoder, with tabs encoded."""
    out, sofar, last = bytearray(), 0, -1

    def output_last():
        nonlocal sofar
        if sofar + 3 > 74:
            out.extend(b"=\n")
            sofar = 0
        out.extend(b"=%02X" % last)
        sofar += 3

    for c in data:
        if c == 10:
            if last != -1:
                output_last()
            out.append(10)
            sofar, last = 0, -1
            continue
        if last != -1:
            if last in QP_SAFE:
                out.append(last)
                sofar += 1
            else:
                output_last()
        if c in QP_SAFE:
            if sofar > 74:
                out.extend(b"=\n")
                sofar = 0
            if c == 32:
                last = c
            else:
                out.append(c)
                sofar += 1
                last = -1
        else:
            if sofar > 72:
                out.extend(b"=\n")
                sofar = 3
            else:
                sofar += 3
            out.extend(b"=%02X" % c)
            last = -1
    if last != -1:
        out.extend(b"=%02X" % last)
    # camel's canonicalisation for signing quotes "From " the same way
    return bytes(re.sub(b"(?m)^From ", b"=46rom ", bytes(out)))


def rewrite_qp_tab(data):
    import quopri

    def edit(head, body_start, body):
        msg = headers_of(head)
        if (msg.get("Content-Transfer-Encoding") or "").strip().lower() != "quoted-printable":
            return []
        if msg.get_content_type().startswith("multipart/") or b"\t" not in body:
            return []
        return [(body_start, body_start + len(body), qp_encode(quopri.decodestring(body)))]
    return edit_entities(data, edit)


def rewrite_trailing(data):
    head, body = split_entity(data)
    return head + b"\n\n" + re.sub(b"[ \t]+\n", b"\n", body)


def rewrite_unfold(data):
    def edit(head, body_start, body):
        start = body_start - len(head) - 2
        if start <= 0:
            return []
        return [(start, start + len(head), re.sub(b"\n[ \t]+", b" ", head))]
    return edit_entities(data, edit)


def rewrite_from(data):
    head, body = split_entity(data)
    return head + b"\n\n" + re.sub(b"(?m)^From ", b">From ", body)


def rewrite_epilogue(data):
    def edit(head, body_start, body):
        msg = headers_of(head)
        if not msg.get_content_type().startswith("multipart/") or not msg.get_param("boundary"):
            return []
        close = body.find(b"--" + msg.get_param("boundary").encode() + b"--")
        if close == -1:
            return []
        end = body.find(b"\n", close)
        end = len(body) if end == -1 else end
        return [(body_start + end, body_start + end, b"\n")]
    return edit_entities(data, edit)


REWRITES = [
    ("preamble", rewrite_preamble),
    ("qp-tab", rewrite_qp_tab),
    ("trailing", rewrite_trailing),
    ("unfold", rewrite_unfold),
    ("from", rewrite_from),
    ("epilogue", rewrite_epilogue),
]


def describe(results):
    return ", ".join(f"{path} {kind}: {result}" for path, kind, result in results) or "no signature"


def main(paths):
    status = 0
    with tempfile.TemporaryDirectory() as tmp:
        for path in paths:
            data = load(path)
            baseline = check(data, tmp)
            print(f"{path}\n  as is      {describe(baseline)}")
            for name, rewrite in REWRITES:
                changed = rewrite(data)
                if changed == data:
                    print(f"  {name:<10} (no change)")
                    continue
                results = check(changed, tmp)
                broken = [r for r, b in zip(results, baseline) if b[2] == "good" and r[2] != "good"]
                if broken:
                    status = 1
                print(f"  {name:<10} {describe(results)}{'   <-- BROKEN' if broken else ''}")
    return status


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
