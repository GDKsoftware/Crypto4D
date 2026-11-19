# Big integer reference cases

`biginteger.json` holds operands with the expected sum, difference, product, quotient, remainder,
comparison, modular power and modular inverse. The expected values were computed with an independent
arbitrary-precision implementation, not with Crypto4D.

The operands cover sizes from 0 up to 4096 bits, with values at and around limb boundaries. `addBackCases`
holds divisions built so that the estimated quotient digit in Knuth's algorithm D is one too large, which
forces the rare add-back step.

A field with the value `null` means that the operation has no result for those operands: a negative
difference, a division by zero or an inverse that does not exist.
