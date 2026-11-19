# Selection from x509-limbo

`selection.json` holds certificates from `limbo.json` of [C2SP/x509-limbo](https://github.com/C2SP/x509-limbo),
taken at commit `f399b0537a1961462338c26690af6236f677e8cf`. x509-limbo is licensed under the Apache License
2.0; see `LICENSE` in this folder.

The file is a selection and a conversion, not a copy. x509-limbo tests the validation of certificate paths,
which Crypto4D does not do, and `limbo.json` is about 40 MB. Its certificates are still useful, because
another program made them. The certificates in `selection.json` are unchanged, as hexadecimal DER instead
of PEM. The expectations are not from x509-limbo: they are what the Python package `cryptography`, version
48.0.0, reports about each certificate.

## Pairs

A pair is a certificate and an issuer certificate from the same x509-limbo test case, where the subject of
the issuer equals the issuer of the certificate. The pairs were sorted into kinds by the outcome of the
signature check, the signature algorithm and the type of the issuer key. The first pairs of every kind were
kept, in the order of `limbo.json`: eight per kind when the signature is valid or invalid, two per kind
otherwise. That gives 52 pairs.

| Field | Meaning |
|-------|---------|
| `testcase` | Identifier of the x509-limbo test case the pair comes from |
| `certificate`, `issuer` | The two certificates as hexadecimal DER |
| `version`, `serialNumber`, `signatureAlgorithm` | Fields of `certificate` according to the reference |
| `issuerKey` | Type of the public key of `issuer` according to the reference |
| `reference` | `valid` or `invalid`: outcome of the signature check by the reference. `not supported by Crypto4D`: the algorithm, the curve or the key size is outside what Crypto4D verifies, and the reference was not asked |
| `explicitCurve` | True when the issuer key states the curve with explicit parameters instead of a name |
| `signedByIssuer` | What `IsSignedBy` must return: true when `reference` is `valid` and `explicitCurve` is false |

21 pairs must verify: ECDSA with a P-256 key, and RSA with a key of 2048, 2052 and 4096 bits. The other 31
must not: signatures that do not match, ECDSA with SHA-1 or SHA-384, RSA with SHA-384 or SHA-512, ML-DSA,
DSA, a P-192 key, an RSA key of 1024 bits and an RSA key that the reference cannot read.

Two pairs come from the test case `webpki::explicit-curve`. The issuer key is a P-256 key that states the
curve with explicit parameters. The reference accepts the signature. Crypto4D only accepts the named curve
`prime256v1` and returns False.

## Certificate with a duplicate extension

`duplicateExtension` is the leaf certificate of the test case `rfc5280::duplicate-extensions`. It names the
same extension twice. The reference parses it and reports the duplicate when the extensions are read;
`TryParse` of Crypto4D returns False.
