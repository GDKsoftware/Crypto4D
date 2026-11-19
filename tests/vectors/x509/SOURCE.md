# X.509 test certificates

The certificates were generated with OpenSSL 3.5.4 (`openssl req -x509` and `openssl x509 -req`):

- `p256.der`, `rsa2048.der` and `ed25519.der` are self-signed
- `leaf_ed25519_signed_by_p256.der` has an Ed25519 key and is signed with the key of `p256.der`

`manifest.json` holds what OpenSSL itself reports about each certificate: the serial number, the
subjectPublicKeyInfo as DER, the signature algorithm and which certificate holds the issuer key. The
parser tests compare the Crypto4D result with these values.

## Certificates with a parameter for ecdsa-with-SHA256

RFC 5758 says that the AlgorithmIdentifier of `ecdsa-with-SHA256` has no parameters. Certificates that
carry an ASN.1 NULL there are in use all the same. Four self-signed certificates with one P-256 key cover
the cases. They were not made with OpenSSL: the DER was put together directly, and the signature over
`tbsCertificate` is valid in all four, so that only the parameters differ.

| File | Inside `tbsCertificate` | Outside | `IsSignedBy` | OpenSSL 3.5.4 `verify -check_ss_sig` |
|------|-------------------------|---------|--------------|--------------------------------------|
| `p256_null_parameter.der` | NULL | NULL | True | OK |
| `p256_null_parameter_inner_only.der` | NULL | absent | False | certificate signature failure |
| `p256_null_parameter_outer_only.der` | absent | NULL | False | certificate signature failure |
| `p256_sequence_parameter.der` | empty SEQUENCE | empty SEQUENCE | False | OK |

The last row is a difference on purpose: OpenSSL accepts the empty SEQUENCE, Crypto4D accepts only absent
and NULL.

The private keys were discarded. The certificates are test data and must not be trusted for anything.
