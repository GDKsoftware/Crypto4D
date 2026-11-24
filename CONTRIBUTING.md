# Contributing to Crypto4D

This page covers what you need to build Crypto4D, run the tests, add test vectors and get a change merged.
Found a security problem? Do not open an issue; follow [SECURITY.md](SECURITY.md) and report it privately.

## What you need

- Delphi 11 or later. The tests run on Delphi 13 only, for Win32, Win64 and Linux64.
- DUnitX, which ships with RAD Studio.
- For Linux64: the Linux SDK in RAD Studio, and a Linux machine or WSL 2 to run the tests on.

The library itself uses only the RTL. Everything else the tests need is in the repository.

## Building and running the tests

From a RAD Studio command prompt in the repository root:

```bat
msbuild tests\Crypto4D.Tests.dproj /t:Build /p:Config=Debug /p:Platform=Win64
tests\bin\Win64\Debug\Crypto4D.Tests.exe
```

Use `/p:Platform=Win32` or `/p:Platform=Linux64` for the other platforms, and `/p:Config=Release` for a
Release build. The Debug configuration has range and overflow checking switched on, so run it at least
once on every platform your change can affect.

A build must finish with zero hints and zero warnings. The test projects switch on W1071 and W1072, the
warnings for implicit integer conversions. Fix such a warning by giving the target the wider type, the way
`Length` returns a `NativeInt`. A cast is fine only where a check right before it proves that the value
fits; never cast just to make the warning go away.

The tests in the category `LargeInput` need about 4 GB of memory on 64-bit platforms. Skip them while you
work with `--exclude:LargeInput`, and run them before you open a pull request.

## Tests

Every change needs tests. Name them `Subject_Scenario_Expectation`, the way the existing fixtures do, for
example `TryRead_ContentOfTwoGiB_ReturnsFalse`. A bug fix starts with a test that fails before the fix.

## Test vectors

Vectors live in `tests\vectors`, one folder per source. Every folder has a `SOURCE.md` that says:

- where the data comes from, with a link and the exact commit, version or file hash;
- whether the files are unmodified copies or a conversion, and if converted, how;
- which records were left out and why;
- under which terms the data may be used.

When the source has its own licence, put a copy of it next to the data as `LICENSE` and add the folder to
the License section of the README. Add the vectors to the list under Testing in the README as well.

Expected results must come from an independent implementation or from the source itself, never from
Crypto4D. The OpenSSL cross-check in `tests\vectors\openssl` is made with
`tests\tools\Crypto4D.VectorGenerator.dproj`; its `SOURCE.md` says how to run it.

## Code style

Follow what is already there: descriptive names without abbreviations, `const` for parameters, inline
variables, a named Boolean for a condition before the `if`, guard clauses instead of deep nesting, an
`else` on every `case`, `Format` for strings that contain values, and one unit per line in a `uses` clause. Every public type and method has an XML documentation comment. Exception messages are in
English and use the exception classes from `Crypto4D.Errors`.

## Pull requests

- One subject per pull request.
- Tests included, and the suite green on the platforms you changed, with zero hints and warnings.
- Update the README when you change public behaviour.

By contributing, you agree that your contribution is released under the [MIT License](LICENSE).
