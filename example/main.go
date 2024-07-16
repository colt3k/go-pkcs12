package main

import (
	"fmt"
	"github.com/colt3k/go-pkcs12"
	"io"
	"log"
	"os"
	"strings"
)

var (
	clientID     = "mytestalias"
	clientSecret string
	vaultKey     = "myvault"
	pkcs12Path   = "./test/test.p12"
)

func main() {
	s := ClientSecret(pkcs12Path, vaultKey, clientID)
	fmt.Printf("sec: %v\n", s)
}

func ClientSecret(pkcs12Path, vaultKey, clientID string) string {
	f, err := os.Open(pkcs12Path)
	if err != nil {
		log.Fatalf("issue loading pkcs12 %v", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatalf("issue reading pkcs12 %v", err)
	}

	blocks, err := pkcs12.ToPEM(b, vaultKey)
	if err != nil {
		log.Fatalf("issue processing pkcs12 %v", err)
	}

	secret := ""
	for _, block := range blocks {
		found := false
		//fmt.Printf("---%s---\n", block.Type)
		for attrKey, attrValue := range block.Headers {
			//if testMode {
			//	fmt.Printf("  %s = %s\n", attrKey, attrValue)
			//}
			if attrKey == "friendlyName" && attrValue == strings.ToLower(clientID) {
				found = true
			}
		}
		if block.Type == "SECRET BAG" && found {
			//if testMode {
			//	fmt.Printf("%v\n", strings.TrimSpace(string(block.Bytes)))
			//}
			secret = string(block.Bytes)
		}
	}
	return secret
}
