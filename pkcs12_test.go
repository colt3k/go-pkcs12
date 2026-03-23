package pkcs12

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sampleP12Base64 = `MIIBrwIBAzCCAVkGCSqGSIb3DQEHAaCCAUoEggFGMIIBQjCCAT4GCSqGSIb3DQEHAaCCAS8E
ggErMIIBJzCCASMGCyqGSIb3DQEMCgEFoIGzMIGwBgsqhkiG9w0BDAoBAqCBoASBnTCBmjBm
BgkqhkiG9w0BBQ0wWTA4BgkqhkiG9w0BBQwwKwQU+39iZwZ6LdNZAd5mQHWCBX0YGZcCAicQ
AgEgMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCUY9LQkWdEjvPRQwyCdjFLBDBiZ0Es
lbxXbwjrMwIqdKgEu7nAwIoBbWKQ3h6iTGUfjXxz2yy+wu6krbhX99GO+WwxXjA5BgkqhkiG
9w0BCRQxLB4qAHIAZwB1AF8AcwBlAGMAcgBlAHQAXwB0AGUAcwB0AF8AYQBsAGkAYQBzMCEG
CSqGSIb3DQEJFTEUBBJUaW1lIDE3NzQyODg4MTAxMzkwTTAxMA0GCWCGSAFlAwQCAQUABCBJ
f+MgnAerxNmsF7khfJV66f3W/gfGBbBhem+uU3FgAQQUcHZKSUiW8Lti2USkBugXd0yGyisC
AicQ`
	sampleP12Password = "test1abc"
	sampleClientAlias = "RGU_SECRET_TEST_ALIAS"
)

func sampleP12Path(t *testing.T) string {
	t.Helper()

	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sampleP12Base64, "\n", ""))
	if err != nil {
		t.Fatalf("decode sample pkcs12: %v", err)
	}

	path := filepath.Join(t.TempDir(), "sample.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write sample pkcs12: %v", err)
	}
	return path
}

// ClientSecret walks the PEM blocks returned by ToPEM and extracts the secret
// bag whose friendlyName matches the requested client ID.
func clientSecret(pkcs12Path, vaultKey, clientID string) (string, error) {
	f, err := os.Open(pkcs12Path)
	if err != nil {
		log.Fatalf("issue loading pkcs12 %v", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("issue reading pkcs12 %v", err)
	}

	blocks, err := ToPEM(b, vaultKey)
	if err != nil {
		return "", fmt.Errorf("issue processing pkcs12 %v", err)
	}

	secret := ""
	for _, block := range blocks {
		found := false
		// fmt.Printf("---%s---\n", block.Type)
		for attrKey, attrValue := range block.Headers {
			// if testMode {
			//	fmt.Printf("  %s = %s\n", attrKey, attrValue)
			// }
			if attrKey == "friendlyName" && attrValue == strings.ToLower(clientID) {
				found = true
			}
		}
		if block.Type == "SECRET BAG" && found {
			// if testMode {
			//	fmt.Printf("%v\n", strings.TrimSpace(string(block.Bytes)))
			// }
			secret = string(block.Bytes)
		}
	}
	return secret, nil
}

func TestToPEMIncludesSecretBags(t *testing.T) {
	path := sampleP12Path(t)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample pkcs12: %v", err)
	}

	blocks, err := ToPEM(data, sampleP12Password)
	if err != nil {
		t.Fatalf("ToPEM() error = %v", err)
	}

	found := 0
	for _, block := range blocks {
		friendlyName, ok := block.Headers["friendlyName"]
		if !ok || block.Type != "SECRET BAG" {
			continue
		}

		content := string(block.Bytes)
		t.Logf("SECRET BAG friendlyName=%q content=%q", friendlyName, content)
		if content != "the_super_secret_value" {
			t.Fatal("SECRET BAG value is incorrect")
		}
		if content == "" {
			t.Fatalf("SECRET BAG content for %q = empty string, want non-empty secret", friendlyName)
		}

		got, err := clientSecret(path, sampleP12Password, friendlyName)
		if err != nil {
			t.Fatalf("ClientSecret() error for %q = %v", friendlyName, err)
		}
		if got != content {
			t.Fatalf("ClientSecret() secret for %q = %q, want %q", friendlyName, got, content)
		}

		found++
	}

	if found == 0 {
		t.Fatal("ToPEM() found no SECRET BAG blocks with friendlyName header")
	}
}

func TestClientSecretReturnsMatchingSecret(t *testing.T) {
	path := sampleP12Path(t)

	want, err := clientSecret(path, sampleP12Password, sampleClientAlias)
	if err != nil {
		t.Fatalf("ClientSecret() error = %v", err)
	}
	if want == "" {
		t.Fatal("ClientSecret() secret = empty string, want matching secret")
	}

	got, err := clientSecret(path, sampleP12Password, strings.ToLower(sampleClientAlias))
	if err != nil {
		t.Fatalf("ClientSecret() error = %v", err)
	}
	if got != want {
		t.Fatalf("ClientSecret() secret = %q, want %q", got, want)
	}
}

func TestClientSecretReturnsEmptyForUnknownClient(t *testing.T) {
	got, err := clientSecret(sampleP12Path(t), sampleP12Password, "missing-client")
	if err != nil {
		t.Fatalf("ClientSecret() error = %v", err)
	}
	if got != "" {
		t.Fatalf("ClientSecret() secret = %q, want empty string", got)
	}
}

func TestClientSecretReturnsReadError(t *testing.T) {
	_, err := clientSecret(t.TempDir(), "myvault", "mytestalias")
	if err == nil {
		t.Fatal("ClientSecret() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "issue reading pkcs12") {
		t.Fatalf("ClientSecret() error = %q, want read error", err.Error())
	}
}

func TestClientSecretReturnsProcessingError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.p12")
	if err := os.WriteFile(path, []byte("not-a-pkcs12"), 0o600); err != nil {
		t.Fatalf("write invalid pkcs12: %v", err)
	}

	_, err := clientSecret(path, "myvault", "mytestalias")
	if err == nil {
		t.Fatal("ClientSecret() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "issue processing pkcs12") {
		t.Fatalf("ClientSecret() error = %q, want processing error", err.Error())
	}
}
