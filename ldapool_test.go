package ldapool

import (
	"os"
	"strconv"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLdapPoolManager(t *testing.T) {
	url := os.Getenv("LDAP_URL")
	if url == "" {
		url = "ldap://localhost:389" // default value
	}

	baseDN := os.Getenv("LDAP_BASE_DN")
	if baseDN == "" {
		baseDN = "dc=example,dc=com" // default value
	}

	maxOpenStr := os.Getenv("LDAP_MAX_OPEN")
	maxOpen := 10 // default value
	if maxOpenStr != "" {
		var err error
		maxOpen, err = strconv.Atoi(maxOpenStr)
		if err != nil {
			t.Fatalf("Invalid LDAP_MAX_OPEN value: %v", err)
		}
	}

	config := LdapConfig{
		Url:     url,
		BaseDN:  baseDN,
		MaxOpen: maxOpen,
	}

	manager, err := NewLdapPoolManager(config)
	if err != nil {
		t.Fatalf("Failed to create LdapPoolManager: %v", err)
	}

	conn, err := manager.Open()
	if err != nil {
		t.Fatalf("Failed to open connection: %v", err)
	}

	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN:       config.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       "(objectClass=*)",
	})

	// printing to show that the query worked
	res.Entries[1].PrettyPrint(2)

	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}

	manager.PutConn(conn)

	if manager.IsClosed() {
		t.Fatalf("Manager should not be closed")
	}

	manager.Close()

	if !manager.IsClosed() {
		t.Fatalf("Manager should be closed")
	}
}
