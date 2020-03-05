package yubitest

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"testing"
)

func TestListKeys(t *testing.T) {
	t.Log("Ok")

	libraryPath := "/usr/local/lib/libykcs11.so"
	ctx := pkcs11.New(libraryPath)

	if ctx == nil {
		t.Fatalf("failed to load library %s", libraryPath)
	}

	if err := ctx.Initialize(); err != nil {
		t.Fatalf("found library %s, but initialize error %s", libraryPath, err.Error())
	}
	info, err := ctx.GetInfo()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Info: %+v\n", info)

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatalf(
			"loaded library %s, but failed to list HSM slots %s", libraryPath, err)
	}
	slot, err := ctx.GetSlotInfo(slots[0])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Slot: %#v\n", slot)

	token, err := ctx.GetTokenInfo(slots[0])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Token: %+v\n", token)

	// CKF_SERIAL_SESSION: TRUE if cryptographic functions are performed in serial with the application; FALSE if the functions may be performed in parallel with the application.
	// CKF_RW_SESSION: TRUE if the session is read/write; FALSE if the session is read-only
	session, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf(
			"loaded library %s, but failed to start session with HSM %s",
			libraryPath, err)
	}

	t.Logf("Initialized PKCS11 library %s and started HSM session", libraryPath)
	_ = session
	/*
		return ctx, session, nil
	*/
}
