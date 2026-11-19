# C2SP CCTV Ed25519 vectors

`ed25519vectors.json` is an unmodified copy of `ed25519/ed25519vectors.json` from
[C2SP/CCTV](https://github.com/C2SP/CCTV), taken at commit `0fb2c3b5dc50437ce3272abcbec7567dde497047`.
`LICENSE` is the license file of that folder (BSD 3-Clause, copyright Google LLC and Filippo Valsorda).

The 914 vectors cover the edge cases of the two curve points in an Ed25519 signature: the public key `A`
and `R`. Every vector has flags that say which edge cases it exercises; the README of the source folder
explains them. The vectors carry no expected result, because verifiers differ on purpose.

Crypto4D rejects a vector that has one of these flags and accepts every other vector:

| Flag | Reason |
|------|--------|
| `low_order_A` | The public key is a point of small order. |
| `non_canonical_A` | The public key is not in its canonical encoding. |
| `non_canonical_R` | `R` is not in its canonical encoding. |
| `low_order_residue` | The signature only verifies after multiplying by the cofactor. |

That leaves 86 accepted vectors. A vector that has no other flags than `low_order_R`,
`low_order_component_A` and `low_order_component_R` is accepted: Crypto4D does not check `R` for small
order and does not require the points to be in the prime-order subgroup.
