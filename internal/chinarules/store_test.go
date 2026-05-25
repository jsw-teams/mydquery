package chinarules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsCNDomainMatchesSuffixByParentDomain(t *testing.T) {
	store := loadTestStore(t, `{
		"source": "test",
		"exacts": ["exact.cn"],
		"suffixes": ["example.cn"],
		"keywords": ["china"],
		"cidr_v4": [],
		"cidr_v6": []
	}`)

	now := time.Now()
	for _, name := range []string{"example.cn", "www.example.cn.", "MiXeD.Example.CN"} {
		if !store.IsCNDomain(name, now) {
			t.Fatalf("expected %q to match suffix rule", name)
		}
	}
	if store.IsCNDomain("notexample.cn", now) {
		t.Fatal("expected unrelated sibling domain not to match suffix rule")
	}
}

func loadTestStore(t *testing.T, content string) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
