# Crypto4D

Crypto4D verifies digital signatures in pure Delphi. The same source compiles for Win32, Win64 and Linux64.

It only verifies. There is no signing, no key generation and no encryption, so the library never handles a
private key.

**This library has not been audited by an external party.** Read the section on testing below and decide
for yourself whether that is enough for your use.

## Supported algorithms

| Algorithm | Class | Notes |
|-----------|-------|-------|
| ECDSA on P-256 with SHA-256 (ES256) | `TEcdsaP256` | Signature as ASN.1 DER or as raw `r \|\| s` (64 bytes) |
| RSA PKCS#1 v1.5 with SHA-256 (RS256) | `TRsaPkcs1Sha256` | Odd modulus from 2048 up to 8192 bits, odd exponent from 3 up to 2^33 - 1 |
| Ed25519 (RFC 8032) | `TEd25519` | Strict variant, see below |
| X.509 certificates | `TX509CertificateInfo` | Parsing, and checking the signature with a given issuer key |

Supporting units: `Crypto4D.BigInteger` (non-negative integers of any size), `Crypto4D.Der` (a strict DER
reader) and `Crypto4D.X509`.

## Requirements

Written for Delphi 11 and later, tested on Delphi 13.

Add the `src` folder to the search path of your project. There is no package to install.

## Return values and exceptions

A verification function returns `False` when the signature does not verify. That includes every kind of
bad input from outside: a damaged signature, a signature of the wrong length, a public key that is not on
the curve, a certificate that does not parse.

`ECrypto4DArgumentError` is raised only when the caller passes something a function can never work with:

- a P-256 public key whose coordinates are not 32 bytes each
- an Ed25519 public key that is not 32 bytes
- an RSA modulus that is even, under 2048 bits or over 8192 bits
- an RSA public exponent that is even, smaller than 3, or 2^33 or larger

When the key comes from outside, check it before you construct it:

- RSA: `TRsaPublicKey.IsSupportedModulus` and `TRsaPublicKey.IsSupportedExponent`
- P-256: both coordinates are 32 bytes, or `TEcdsaP256PublicKey.IsUncompressedPoint` for the 65 byte form
- Ed25519: the key is 32 bytes (`TEd25519.PublicKeySize`)
- a key from a certificate or a SubjectPublicKeyInfo: `TryGetEcdsaP256Key`, `TryGetRsaKey` and
  `TryGetEd25519Key` do these checks and return `False`

A P-256 key of the right length that is not a point on the curve does not raise. The verification returns
`False` for it.

`TBigInteger` raises `ECrypto4DArithmeticError` for a division by zero, a subtraction with a negative
result and a modular inverse that does not exist. All exceptions descend from `ECrypto4DError`.

## Usage

### ECDSA P-256 with SHA-256

```delphi
uses
  Crypto4D.Ecdsa;

function IsSignedByKey(const X, Y, Message, DerSignature: TBytes): Boolean;
begin
  const Key = TEcdsaP256PublicKey.FromCoordinates(X, Y);
  Result := TEcdsaP256.VerifyDer(Key, Message, DerSignature);
end;
```

`TEcdsaP256PublicKey.FromUncompressedPoint` takes the 65 byte form `04 || X || Y`. `TEcdsaP256.VerifyRaw`
takes the signature as 64 bytes `r || s`.

The public key must be a point on the curve, and `r` and `s` must be in the range from 1 up to and
including n - 1. A DER signature must be strict DER: a non-minimal length or integer encoding is rejected.
A signature with a high `s` value is accepted; there is no low-S rule.

### RSA PKCS#1 v1.5 with SHA-256

```delphi
uses
  Crypto4D.Rsa;

function IsSignedByKey(const Modulus, Exponent, Message, Signature: TBytes): Boolean;
begin
  const Key = TRsaPublicKey.Create(Modulus, Exponent);
  Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
end;
```

Modulus and exponent are big-endian byte arrays. The signature must be exactly as long as the modulus.
Crypto4D builds the one encoded message that is valid for the given message and compares it byte for byte
with the decrypted signature; it does not parse the padding. A `DigestInfo` without the `NULL` parameter
is therefore rejected.

The modulus and the exponent have an upper limit because the other party picks the key, and the time one verification takes grows
with the size of the modulus and of the exponent.

### Ed25519

```delphi
uses
  Crypto4D.Ed25519;

function IsSignedByKey(const PublicKey, Message, Signature: TBytes): Boolean;
begin
  Result := TEd25519.Verify(PublicKey, Message, Signature);
end;
```

The verification is strict:

- `S` must be smaller than the group order L
- a public key or `R` in a non-canonical encoding is rejected
- a public key of small order is rejected
- the equation `[S]B = R + [k]A` is checked as it stands, without multiplying by the cofactor 8

Strict does not mean that the public key must lie in the prime-order subgroup: a key with a torsion
component that is not of small order (a mixed-order key) is accepted, and its signatures verify when they
satisfy the equation as it stands.

Only the public key is checked for small order. `R` is not: a signature whose `R` is one of the eight points
of small order is accepted when the equation holds. Case 2 of ed25519-speccheck is such a signature.

Other libraries draw the line elsewhere. The README of the
[C2SP CCTV Ed25519 vectors](https://github.com/C2SP/CCTV/tree/main/ed25519) lists their behaviour:

- Go, OpenSSL and `verify` of ed25519-dalek accept a public key of small order and a public key in a
  non-canonical encoding. Crypto4D rejects both.
- `verify_strict` of ed25519-dalek rejects an `R` of small order. Crypto4D accepts it.
- A ZIP 215 verifier accepts non-canonical encodings and multiplies by the cofactor. Crypto4D does neither.

### X.509 certificates

```delphi
uses
  Crypto4D.X509;

function IsIssuedBy(const CertificateDer, IssuerDer: TBytes): Boolean;
begin
  var Certificate: TX509CertificateInfo;
  var Issuer: TX509CertificateInfo;
  const BothParse = TX509CertificateInfo.TryParse(CertificateDer, Certificate) and
                    TX509CertificateInfo.TryParse(IssuerDer, Issuer);
  if not BothParse then
    Exit(False);

  Result := Certificate.IsSignedBy(Issuer.PublicKey);
end;
```

A parsed certificate gives access to the bytes of `tbsCertificate`, the serial number, issuer, validity
and subject as DER, the subject public key with its algorithm, both signature algorithm identifiers, the
signature and the extensions as raw values (`TryFindExtension`). `TX509PublicKeyInfo` converts the public
key to the key types above with `TryGetEcdsaP256Key`, `TryGetRsaKey` and `TryGetEd25519Key`.

`IsSignedBy` supports `ecdsa-with-SHA256` with a P-256 key, `sha256WithRSAEncryption` and `Ed25519`.

The parameters of the signature AlgorithmIdentifier may be absent or an ASN.1 `NULL` for
`ecdsa-with-SHA256` and `sha256WithRSAEncryption`, and must be absent for `Ed25519`. RFC 5758 says they
must be absent for ECDSA, but certificates with a `NULL` are in use, among them attestation root
certificates in the FIDO Metadata Service, and OpenSSL accepts them. The identifier inside
`tbsCertificate` and the one outside it must be equal, parameters included, and any other parameter is
rejected.

`TryParse` reads the structure of a certificate as strict DER. It also rejects a certificate that states version 1 explicitly, has a
serial number that is not in its shortest encoding, holds a unique identifier in version 1 or extensions
below version 3, or names an extension twice.

`TryParse` checks the structure, not the meaning. Issuer, validity and subject only have to be a SEQUENCE
and are kept as DER. The value of an extension is not read. The parameters of an algorithm that Crypto4D
does not know can be any single DER element.

Crypto4D does not validate a certificate chain. It has no trust store and it does not look at validity
dates, key usage, name constraints or revocation. `IsSignedBy` answers one question: was this certificate
signed with that key.

### Big integers

```delphi
uses
  Crypto4D.BigInteger;

const Modulus = TBigInteger.FromHex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const Value   = TBigInteger.FromBytes(SomeBigEndianBytes);
const Inverse = Value.ModInverse(Modulus);
const Power   = Value.ModPow(TBigInteger.FromUInt64(65537), Modulus);
```

`TBigInteger` holds non-negative values of any size and is immutable.

## No constant-time guarantee

Verification works with public data only, so the code makes no attempt to run in constant time. Do not
reuse the arithmetic in this library for anything that involves a secret.

## Testing

The test project is `tests\Crypto4D.Tests.dproj`, a DUnitX console application. The Debug configuration
has overflow and range checking switched on.

The tests were run with Delphi 13, as Debug and as Release build, for Win32, Win64 and Linux64. The Linux64
build was made with the SDK of Ubuntu 24.04 and run on Ubuntu 24.04 under WSL 2. No other Delphi version
and no other platform was run. [CONTRIBUTING.md](CONTRIBUTING.md) says how to build and run them.

What the tests cover:

- [Wycheproof](https://github.com/C2SP/wycheproof) test vectors for ECDSA P-256 with SHA-256 (DER and
  P1363), Ed25519 and RSA PKCS#1 v1.5 with SHA-256 for 2048, 3072, 4096 and 8192 bit keys. Every `valid`
  vector must verify and every `invalid` vector must be rejected.
- The Ed25519 test vectors of RFC 8032 section 7.1.
- The 914 Ed25519 vectors of [C2SP CCTV](https://github.com/C2SP/CCTV/tree/main/ed25519), which cover the
  edge cases of the public key and of `R`. Crypto4D rejects every vector with the flag `low_order_A`,
  `non_canonical_A`, `non_canonical_R` or `low_order_residue` and accepts the other 86.
- The 12 cases of [ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck). Crypto4D accepts
  cases 2 and 3 and rejects the other ten; `tests\vectors\ed25519-speccheck\SOURCE.md` gives the reason
  per case.
- The 1024 signatures of the regression test `sign.input` from ed25519.cr.yp.to. All verify, and none
  verifies after one bit of the signature is flipped.
- NIST CAVP signature verification vectors: 15 for ECDSA with P-256 and SHA-256, and 35 for RSA PKCS#1 v1.5
  with SHA-256 and a 2048 or 3072 bit modulus.
- 52 pairs of a certificate and its issuer certificate from
  [x509-limbo](https://github.com/C2SP/x509-limbo), with the outcome of the Python package `cryptography` as
  expectation. The selection includes signatures that do not match, algorithms and key sizes that Crypto4D
  does not support, and a P-256 key with explicit curve parameters, which Crypto4D rejects.
- A cross-check against OpenSSL: 2960 cases with keys and signatures made by OpenSSL. About half are
  damaged by flipping one bit in the signature, the message or the public key. OpenSSL decides the
  expected outcome of every case.
- Big integer arithmetic against results computed by an independent arbitrary-precision implementation,
  including divisions that need the rare add-back step of Knuth's algorithm D.
- X.509 certificates made by OpenSSL, compared with what OpenSSL reports about them, plus damaged and
  truncated variants.
- Sizes beyond 2^31: a 4 GiB message, a 2 GiB DER element and an RSA modulus of more than 2^32 bits.

The vectors are in `tests\vectors`. Every folder there has a `SOURCE.md` that says where the data comes
from.

### Wycheproof vectors with the result "acceptable"

Wycheproof marks a vector `acceptable` when a library may accept or reject it. Crypto4D decides per flag:

| Flag | Vectors | Crypto4D | Reason |
|------|---------|----------|--------|
| `MissingNull` (RSA) | 4 | rejects | The `DigestInfo` has no `NULL` parameter. Wycheproof calls these signatures invalid but tolerated by some legacy libraries. Crypto4D compares against the one correct encoding. |
| `SmallOrderPublicKey` (Ed25519) | 8 | rejects | The public key is one of the eight points of small order. Crypto4D rejects such keys. |
| `MixedOrderPublicKey` (Ed25519) | 21 | accepts all 21 | The public key has a torsion component but is not of small order, so Crypto4D does not reject the key. Each of these signatures also satisfies the equation without the cofactor, which an independent implementation confirmed (see `tests\vectors\wycheproof\SOURCE.md`). |

## License

MIT, see [LICENSE](LICENSE).

Test vectors from other projects keep their own license. The vectors in `tests\vectors\wycheproof`,
`tests\vectors\ed25519-speccheck` and `tests\vectors\x509-limbo` are licensed under the Apache License
2.0 and those in `tests\vectors\cctv` under a BSD 3-Clause license; each of these folders has a `LICENSE`
file. `SOURCE.md` in `tests\vectors\ed25519-cr-yp-to` and `tests\vectors\nist-cavp` states the terms of
those vectors.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and, for reporting a vulnerability, [SECURITY.md](SECURITY.md).
