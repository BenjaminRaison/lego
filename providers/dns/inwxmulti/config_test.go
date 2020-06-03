package inwxmulti

import (
	"testing"
)

const path = "data/"

func TestReadAccount(t *testing.T) {
	account, err := readAccount(path+"account1.json", []string{"example.com", "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if account.InwxUsername != "user1" || account.InwxPassword != "password1" || account.InwxSharedSecret != "ABCD1234" {
		t.Fatal("Failed to parse account")
	}
	if len(account.Domains) != 2 || account.Domains[0] != "example.com" || account.Domains[1] != "example.net" {
		t.Fatal("domains not set on account")
	}
}

func TestReadAccount_FileNotFound(t *testing.T) {
	_, err := readAccount(path+"notfound", []string{"example.com"})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestReadAccount_Invalid(t *testing.T) {
	_, err := readAccount(path+"accountInvalid.json", []string{"example.com"})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestReadAccount_MissingCredentials(t *testing.T) {
	_, err := readAccount(path+"accountMissing.json", []string{"example.com"})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestGetAccounts(t *testing.T) {
	accounts, err := getAccounts(path + "accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(accounts))
	}
	if len(accounts[0].Domains) != 1 || len(accounts[1].Domains) != 2 {
		t.Fatal("Failed to set domains for accounts")
	}
}

func TestGetAccounts_NotFound(t *testing.T) {
	_, err := getAccounts(path + "not found")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestGetAccounts_Invalid(t *testing.T) {
	_, err := getAccounts(path + "account1.json")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}
