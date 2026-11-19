# Wycheproof test vectors

The `*_test.json` files in this folder are unmodified copies from the `testvectors_v1` folder of
[C2SP/wycheproof](https://github.com/C2SP/wycheproof), taken at commit
`65ca494727a52944c204441c860b039e6786b99b`.

They are licensed under the Apache License 2.0; see `LICENSE` in this folder.

`ed25519_mixed_order_expected.json` is not part of Wycheproof. Wycheproof marks the Ed25519 vectors with
the flag `MixedOrderPublicKey` as "acceptable": a verifier may accept or reject them. Crypto4D checks the
equation `[S]B = R + [k]A` without multiplying by the cofactor, so the outcome depends on the vector. The
file lists per vector whether that equation holds. It was computed with an independent Ed25519 verifier on
arbitrary-precision integers and affine coordinates, not with Crypto4D.
