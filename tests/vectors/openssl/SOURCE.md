# OpenSSL cross-check cases

`crosscheck.json` is written by the console project `tests\tools\Crypto4D.VectorGenerator.dproj`, which
drives the `openssl` command line tool. The `openssl` field in the file names the OpenSSL version used.

OpenSSL generates the key pairs (P-256, RSA 2048, 3072 and 4096, Ed25519) and signs a random message for
every case. About half of the cases are then damaged by flipping one bit in the signature, the message or
the public key. OpenSSL verifies every case, damaged or not, and its verdict is stored as `expected` and
`opensslVerdict`. The Crypto4D tests must reach the same verdict.

Notes:

- Ed25519 messages have at least one byte, because `openssl pkeyutl` cannot read an empty message.
- A damaged RSA modulus keeps its top byte, so the key keeps its size.
- For ECDSA the `signature` mutation flips a bit in `r` or `s` and encodes the result as DER again; the
  `signature-der` mutation flips a bit in the DER encoding itself, and such a case has no `rawSignature`.

To make the file again:

```
tests\tools\bin\Win64\Debug\Crypto4D.VectorGenerator.exe <path to openssl.exe> tests\vectors\openssl\crosscheck.json
```

The keys are new on every run, so the file differs from run to run.
