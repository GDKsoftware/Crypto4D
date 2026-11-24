# Contributing to Crypto4D

Found a security problem? Do not open an issue; follow [SECURITY.md](SECURITY.md).

## Building and running the tests

You need Delphi 13 with DUnitX, which ships with RAD Studio. For Linux64 you also need the Linux SDK and a
Linux machine or WSL 2. From a RAD Studio command prompt in the repository root:

```bat
msbuild tests\Crypto4D.Tests.dproj /t:Build /p:Config=Debug /p:Platform=Win64
tests\bin\Win64\Debug\Crypto4D.Tests.exe
```

Use `/p:Platform=Win32` or `Linux64` for the other platforms. The Debug configuration has range and
overflow checking switched on.

A build must finish with zero hints and zero warnings, W1071 and W1072 included. Fix those by giving the
target the wider type; a cast is fine only right after a check that proves the value fits.

The tests in the category `LargeInput` need about 4 GB of memory. Skip them while you work with
`--exclude:LargeInput`.

## Tests

Every change needs tests, named `Subject_Scenario_Expectation`. A bug fix starts with a test that fails
before the fix.

## Test vectors

Vectors live in `tests\vectors`, one folder per source. Its `SOURCE.md` says where the data comes from (with
the exact commit, version or file hash), what was converted or left out, and under which terms it may be
used. A source with its own licence gets a copy of it as `LICENSE` in that folder and a line in the License
section of the README.

Expected results come from the source or from an independent implementation, never from Crypto4D.

## Pull requests

One subject per pull request. Follow the style of the code around your change, and update the README when
you change public behaviour. By contributing, you agree that your contribution is released under the
[MIT License](LICENSE).
