# NIST CAVP signature verification vectors

Both files are conversions of response files from the example test vectors of the NIST Cryptographic
Algorithm Validation Program,
<https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>.

| File | Source archive | Source file | Records taken |
|------|----------------|-------------|---------------|
| `ecdsa_p256_sha256_sigver.json` | `186-4ecdsatestvectors.zip` | `SigVer.rsp` | The 15 records of the section `[P-256,SHA-256]` |
| `rsa_pkcs1_sha256_sigver.json` | `186-3rsatestvectors.zip` | `SigVer15_186-3.rsp` | 35 records with `SHAAlg = SHA256` under `[mod = 2048]` and `[mod = 3072]` |

The archives have no version number. The copies that were converted have these SHA-256 hashes:

- `186-4ecdsatestvectors.zip`: `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752`
- `186-3rsatestvectors.zip`: `8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c`

The conversion copies the values of every record in the order of the source: `Qx`, `Qy`, `Msg`, `R`, `S`
and `Result` for ECDSA, and `n`, `e`, `Msg`, `S` and `Result` for RSA. `Result` starts with `P` when the
signature must verify and with `F` when it must be rejected. The private exponent `d` is left out.

The source has 36 RSA records for SHA-256 with a 2048 or 3072 bit modulus. One of them, with `mod = 2048`,
`e = 7485b` and `Result = F`, has a message of 255 hexadecimal digits, which is not a whole number of
bytes. That record is left out. No value was changed in the other records.

## Terms

This data/work was created by employees of the National Institute of Standards and Technology (NIST), an
agency of the Federal Government. Pursuant to title 17 United States Code Section 105, works of NIST
employees are not subject to copyright protection in the United States. This data/work may be subject to
foreign copyright.

The data/work is provided by NIST as a public service and is expressly provided "AS IS." NIST MAKES NO
WARRANTY OF ANY KIND, EXPRESS, IMPLIED OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST does not
warrant or make any representations regarding the use of the data or the results thereof, including but
not limited to the correctness, accuracy, reliability or usefulness of the data. NIST SHALL NOT BE LIABLE
AND YOU HEREBY RELEASE NIST FROM LIABILITY FOR ANY INDIRECT, CONSEQUENTIAL, SPECIAL, OR INCIDENTAL DAMAGES
(INCLUDING DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, AND
THE LIKE), WHETHER ARISING IN TORT, CONTRACT, OR OTHERWISE, ARISING FROM OR RELATING TO THE DATA (OR THE
USE OF OR INABILITY TO USE THIS DATA), EVEN IF NIST HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

This is the statement that NIST asks to include with its data. It comes from
<https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications>,
which has the full text, including the license that NIST grants where it holds copyright outside the
United States.
