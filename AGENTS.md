# Repository Guidelines

## Project Structure & Module Organization
The module root contains the narrowed `pkcs12` library and most implementation files, including `pkcs12.go`, `crypto.go`, `mac.go`, `pbkdf.go`, `safebags.go`, and `errors.go`. Tests live beside the code as `*_test.go`; the root package now focuses on `ToPEM` secret-bag extraction plus the low-level helpers that path still needs. The internal RC2 implementation remains isolated under `internal/rc2/` with its own tests and benchmarks. The active module path is `github.com/colt3k/go-pkcs12`.

## Build, Test, and Development Commands
Use `go build -mod=mod ./...` to build every package. Use `go test -mod=mod ./...` for the full suite and `go test -mod=mod ./internal/rc2` for the clean RC2 package target. Run `go test -mod=mod -bench . ./internal/rc2` when changing cipher internals. `-mod=mod` is currently required because `vendor/modules.txt` is out of sync with `go.mod`.

## Coding Style & Naming Conventions
Follow standard Go conventions: tabs for indentation, `gofmt` for formatting, lowercase package names, and mixedCaps identifiers. Keep exported names descriptive and stable, and mirror feature files with matching test files such as `mac.go` and `mac_test.go`. Prefer small, focused helpers near the code they support. No dedicated linter config is checked in, so `gofmt -w` is the minimum formatting step before review.

## Testing Guidelines
Use the standard `testing` package. Name tests `TestXxx` and benchmarks `BenchmarkXxx`. Keep fixtures deterministic and repository-local. When changing parsing or crypto behavior, add both success and failure coverage in the nearest `*_test.go`. The root-package suite should stay green under Go 1.24 with `-mod=mod`.

## Commit & Pull Request Guidelines
Recent history favors short, lowercase, imperative commit subjects such as `update deps` and `remove yubikey support and fix for CVE`. Keep the first line concise and scoped to one logical change. PRs should explain behavioral impact, list the exact commands you ran, and mention vendor or fixture updates separately. For crypto-sensitive changes, include compatibility notes or sample inputs and outputs rather than screenshots.
