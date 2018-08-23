package crytpo

import "testing"

func TestHashPassword(t *testing.T) {
	password := "correct horse battery staple"
	hash, err := HashPassword(password, Algorithm_Bcrypt)
	if err != nil {
		t.Error(err)
	}
	result, err := VerifyHash(password, hash, Algorithm_Bcrypt)
	if err != nil {
		t.Error(err)
	}
	if !result {
		t.Errorf("Verification was incorrect, got: %t, want: %t.", result, true)
	}
}

func TestHashPassword_Mismatch(t *testing.T) {
	password := "correct horse battery staple"
	password2 := "badpassword"
	hash, err := HashPassword(password, Algorithm_Bcrypt)
	if err != nil {
		t.Error(err)
	}
	result, err := VerifyHash(password2, hash, Algorithm_Bcrypt)
	if err != nil {
		t.Error(err)
	}
	if result {
		t.Errorf("Verification was incorrect, got: %t, want: %t.", result, true)
	}
}
