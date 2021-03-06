package pkcs12

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

const testP12 = `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
8H7s9Y4eUJHjgZmaWRA5MRmg+tQCAwGGoA==`

func TestMyPEM(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(testP12)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := ToPEM(data, "changeit")
	if err != nil {
		//fmt.Println(err.Error())
		t.Fatalf("%+v", err)
	}
	for _, block := range pem {
		fmt.Printf("---%s---\n", block.Type)
		for attrKey, attrValue := range block.Headers {
			fmt.Printf("  %s = %s\n", attrKey, attrValue)
		}

		if block.Type == "PRIVATE KEY" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				//t.Log(err)
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					//t.Log(err)
					key, err = x509.ParseECPrivateKey(block.Bytes)
				}
			}
			if key != nil {
				fmt.Printf("Key: %#v\n", key)
			}
		} else if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("%+v", err)
			}
			fmt.Printf("  Subject: %s\n", cert.Subject.String())
		}

	}

}

func Test1(t *testing.T) {
	input := `Instance name: ROOT\0004
`
	re := regexp.MustCompile("Instance name:(.*)")
	instanceName := re.FindStringSubmatch(input)[1]
	fmt.Println(strings.TrimSpace(instanceName))
}
func TestErrType(t *testing.T) {
	fset := token.NewFileSet()
	// Parse src but stop after processing the imports.
	f, err := parser.ParseFile(fset, "pkcs12.go", nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the imports from the file's AST.

	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}

		retTypes := fn.Type.Results.List
		if len(retTypes) == 0 {
			continue
		}
		lastRetType := retTypes[len(retTypes)-1]

		fmt.Println(fn.Name.Name, lastRetType.Type)
	}
}
