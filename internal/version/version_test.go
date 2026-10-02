package version

import "testing"

func TestString(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("String() = %q, want v1.2.3", got)
	}
	Version = ""
	if got := String(); got != "dev" {
		t.Fatalf("String() with empty Version = %q, want dev", got)
	}
}
