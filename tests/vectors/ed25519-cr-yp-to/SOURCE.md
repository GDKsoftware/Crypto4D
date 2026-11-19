# Ed25519 regression test from ed25519.cr.yp.to

`sign_input.json` is a conversion of <https://ed25519.cr.yp.to/python/sign.input>, the data file of the
signature regression test that belongs to the Python implementation on
<https://ed25519.cr.yp.to/software.html>. The source file has no version; the copy that was converted has
the SHA-256 hash `8db1fea94f4e78958aac6e839b483cdd79096d1fe478285f15164f9e58361baf`.

That page states: "The Ed25519 software is in the public domain."

The source has 1024 lines, each with four fields separated by colons: the secret key followed by the public
key, the public key, the message, and the signature followed by the message, all in hexadecimal. The
conversion keeps the public key, the message and the 64 byte signature of every line, in the order of the
source, and drops the secret key. No value was changed.

Every signature is valid.
