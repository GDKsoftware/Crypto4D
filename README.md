# Crypto4D

Crypto4D verifies digital signatures in pure Delphi. It needs no DLL, no OpenSSL and no unit outside the
Delphi RTL, and the same source compiles for Win32, Win64 and Linux64.

It only verifies. There is no signing, no key generation and no encryption, so the library never handles a
private key.

**This library has not been audited by an external party.** Read the section on testing below and decide
for yourself whether that is enough for your use.

## Supported algorithms

| Algorithm | Class | Notes |
|-----------|-------|-------|
| ECDSA on P-256 with SHA-256 (ES256) | `TEcdsaP256` | Signature as ASN.1 DER or as raw `r \|\| s` (64 bytes) |
| RSA PKCS#1 v1.5 with SHA-256 (RS256) | `TRsaPkcs1Sha256` | Modulus from 2048 up to 16384 bits, odd exponent from 3 up to 2^64 - 1 |
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
- an RSA modulus under 2048 or over 16384 bits
- an RSA public exponent that is even, smaller than 3, or 2^64 or larger

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

Two limits apply to the key, and `TRsaPublicKey.Create` raises `ECrypto4DArgumentError` for a key outside
them:

- the modulus must be at least 2048 and at most 16384 bits
- the public exponent must be odd, at least 3 and smaller than 2^64

The upper limits keep the cost of one verification bounded when the key comes from an untrusted party.

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

Strict here means that Crypto4D rejects everything in the list above: an `S` that is not reduced, a
non-canonical encoding, a public key of small order and a signature that only verifies after multiplying
by the cofactor, so this is not the ZIP 215 rule set. Strict does not mean that the public key must lie in
the prime-order subgroup: a key with a torsion component that is not of small order (a mixed-order key) is
accepted, and its signatures verify when they satisfy the equation as it stands.

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

`TryParse` reads the structure of a certificate as strict DER. It also rejects a certificate that states version 1 explicitly, has a
serial number that is not in its shortest encoding, holds a unique identifier in version 1 or extensions
below version 3, or names an extension twice. Issuer, validity and subject are kept as DER; their content
is not parsed.

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

```
msbuild tests\Crypto4D.Tests.dproj /t:Build /p:Config=Debug /p:Platform=Win64
tests\bin\Win64\Debug\Crypto4D.Tests.exe
```

What the tests cover:

- [Wycheproof](https://github.com/C2SP/wycheproof) test vectors for ECDSA P-256 with SHA-256 (DER and
  P1363), Ed25519 and RSA PKCS#1 v1.5 with SHA-256 for 2048, 3072 and 4096 bit keys. Every `valid` vector
  must verify and every `invalid` vector must be rejected.
- The Ed25519 test vectors of RFC 8032 section 7.1.
- A cross-check against OpenSSL: 2960 cases with keys and signatures made by OpenSSL. About half are
  damaged by flipping one bit in the signature, the message or the public key. OpenSSL decides the
  expected outcome of every case.
- Big integer arithmetic against results computed by an independent arbitrary-precision implementation,
  including divisions that need the rare add-back step of Knuth's algorithm D.
- X.509 certificates made by OpenSSL, compared with what OpenSSL reports about them, plus damaged and
  truncated variants.

The vectors are in `tests\vectors`. Every folder there has a `SOURCE.md` that says where the data comes
from.

The OpenSSL cross-check cases can be made again with `tests\tools\Crypto4D.VectorGenerator.dproj`, a
console program that drives the `openssl` command line tool:

```
msbuild tests\tools\Crypto4D.VectorGenerator.dproj /t:Build /p:Config=Debug /p:Platform=Win64
tests\tools\bin\Win64\Debug\Crypto4D.VectorGenerator.exe <path to openssl.exe> tests\vectors\openssl\crosscheck.json
```

### Wycheproof vectors with the result "acceptable"

Wycheproof marks a vector `acceptable` when a library may accept or reject it. Crypto4D decides per flag:

| Flag | Vectors | Crypto4D | Reason |
|------|---------|----------|--------|
| `MissingNull` (RSA) | 3 | rejects | The `DigestInfo` has no `NULL` parameter. Wycheproof calls these signatures invalid but tolerated by some legacy libraries. Crypto4D compares against the one correct encoding. |
| `SmallOrderPublicKey` (Ed25519) | 8 | rejects | The public key is one of the eight points of small order. Crypto4D rejects such keys. |
| `MixedOrderPublicKey` (Ed25519) | 21 | accepts all 21 | The public key has a torsion component but is not of small order, so Crypto4D does not reject the key. Each of these signatures also satisfies the equation without the cofactor, which an independent implementation confirmed (see `tests\vectors\wycheproof\SOURCE.md`). |

## License

MIT, see [LICENSE](LICENSE). The Wycheproof test vectors in `tests\vectors\wycheproof` are licensed under
the Apache License 2.0, see the `LICENSE` file in that folder.
