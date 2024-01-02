module github.com/colt3k/go-pkcs12

go 1.17

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/crypto v0.17.0
)
replace golang.org/x/net => golang.org/x/net v0.19.0 //CVE-2023-48795
