# ed25519-speccheck cases

`cases.json` is an unmodified copy from
[novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck), taken at commit
`5e4bfc4542293286e9ad3cb2b805badee00503de`. It is licensed under the Apache License 2.0; see `LICENSE` in
this folder.

The file holds 12 signatures, numbered from 0 in the order of the file. The README of the source describes
how each one was built. The file carries no expected result. Crypto4D behaves as follows:

| Case | Built as | Crypto4D | Reason |
|------|----------|----------|--------|
| 0 | `S` = 0, public key and `R` of small order | rejects | The public key is of small order. |
| 1 | Public key of small order, `R` of mixed order | rejects | The public key is of small order. |
| 2 | Public key of mixed order, `R` of small order | accepts | The equation holds without the cofactor, and `R` is not checked for small order. |
| 3 | Public key and `R` of mixed order | accepts | The equation holds without the cofactor, and a public key of mixed order is allowed. |
| 4 | Public key and `R` of mixed order | rejects | The equation only holds after multiplying by the cofactor. |
| 5 | Public key of mixed order, `R` of order L | rejects | The equation only holds after multiplying by the cofactor. |
| 6 | `S` above L | rejects | `S` must be smaller than L. |
| 7 | `S` far above L | rejects | `S` must be smaller than L. |
| 8 | `R` in a non-canonical encoding | rejects | `R` must be in its canonical encoding. |
| 9 | `R` in a non-canonical encoding | rejects | `R` must be in its canonical encoding. |
| 10 | Public key in a non-canonical encoding, of small order | rejects | The public key must be in its canonical encoding and not of small order. |
| 11 | Public key in a non-canonical encoding, of small order | rejects | The public key must be in its canonical encoding and not of small order. |

Mixed order means that the point has a torsion component but is not one of the eight points of small order.
