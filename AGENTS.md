# Repository Guidelines

## Project Structure & Module Organization
The module root contains the `pkcs12` library and most implementation files, including `pkcs12.go`, `crypto.go`, `mac.go`, `pbkdf.go`, `safebags.go`, and `errors.go`. Tests live beside the code as `*_test.go`. The internal RC2 implementation is isolated under `internal/rc2/` with its own tests and benchmarks. `example/` holds a small sample program, and `test/create_pkcs12.sh` regenerates a sample keystore; the checked-in fixture is `test.p12` at the repository root. The active module path is `github.com/colt3k/go-pkcs12`, even though some upstream comments still mention SSLMate’s import path.

## Build, Test, and Development Commands
Use `go build -mod=mod ./...` to build every package. Use `go test -mod=mod ./...` for the full suite and `go test -mod=mod ./internal/rc2` for the clean RC2 package target. Run `go test -mod=mod -bench . ./internal/rc2` when changing cipher internals. Use `go run ./example` to exercise the sample program after pointing it at a local `.p12` file. `-mod=mod` is currently required because `vendor/modules.txt` is out of sync with `go.mod`.

## Coding Style & Naming Conventions
Follow standard Go conventions: tabs for indentation, `gofmt` for formatting, lowercase package names, and mixedCaps identifiers. Keep exported names descriptive and stable, and mirror feature files with matching test files such as `mac.go` and `mac_test.go`. Prefer small, focused helpers near the code they support. No dedicated linter config is checked in, so `gofmt -w` is the minimum formatting step before review.

## Testing Guidelines
Use the standard `testing` package. Name tests `TestXxx` and benchmarks `BenchmarkXxx`. Keep fixtures deterministic and repository-local. When changing parsing or crypto behavior, add both success and failure coverage in the nearest `*_test.go`. At the moment, several root-package tests fail under Go 1.24 even with `-mod=mod`; do not hide those baseline failures in a PR, and call out whether your change affects them.

## Commit & Pull Request Guidelines
Recent history favors short, lowercase, imperative commit subjects such as `update deps` and `remove yubikey support and fix for CVE`. Keep the first line concise and scoped to one logical change. PRs should explain behavioral impact, list the exact commands you ran, and mention vendor or fixture updates separately. For crypto-sensitive changes, include compatibility notes or sample inputs and outputs rather than screenshots.
