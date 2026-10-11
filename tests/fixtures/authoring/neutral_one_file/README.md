# One-file external authoring example

Build `hello.c` using the compiler for the target machine and place the finalized
executable at `final/hello` relative to `project.json`. On Windows, use the same
filename in the project definition as the finalized executable, such as
`final/hello.exe` and `bin/hello.exe`.

From the repository root, create an empty output directory outside this fixture
and run:

```text
python tools/usk_bundle_author.py build --source tests/fixtures/authoring/neutral_one_file/project.json --target neutral-local --output-dir <empty-output-directory>
python tools/usk_bundle_author.py inspect --bundle <empty-output-directory>/product.bundle.json
python tools/usk_bundle_author.py resolve --bundle <empty-output-directory>/product.bundle.json
```

The authoring tool reads the finalized executable; it does not compile or run
it. The current output is an unsigned local payload archive plus a target bundle
sidecar. It is not yet a setup application, signed release, or qualified carrier.
