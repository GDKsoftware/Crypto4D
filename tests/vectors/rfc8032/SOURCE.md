# RFC 8032 test vectors

`ed25519.json` holds the five Ed25519 test vectors of RFC 8032 section 7.1 (TEST 1, TEST 2, TEST 3,
TEST 1024 and TEST SHA(abc)): public key, message and signature, copied from the text of the RFC at
https://www.rfc-editor.org/rfc/rfc8032.txt. The secret keys are left out, because Crypto4D only verifies.
