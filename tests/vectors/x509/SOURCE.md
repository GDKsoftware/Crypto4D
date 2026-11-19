# X.509 test certificates

The certificates were generated with OpenSSL 3.5.4 (`openssl req -x509` and `openssl x509 -req`):

- `p256.der`, `rsa2048.der` and `ed25519.der` are self-signed
- `leaf_ed25519_signed_by_p256.der` has an Ed25519 key and is signed with the key of `p256.der`

`manifest.json` holds what OpenSSL itself reports about each certificate: the serial number, the
subjectPublicKeyInfo as DER, the signature algorithm and which certificate holds the issuer key. The
parser tests compare the Crypto4D result with these values.

The private keys were discarded. The certificates are test data and must not be trusted for anything.
