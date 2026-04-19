package config

import (
	"strings"
	"testing"
)

func TestParseBoolExplicit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in         string
		wantParsed bool
		wantOK     bool
	}{
		{"", false, true},
		{"1", true, true},
		{"true", true, true},
		{"TRUE", true, true},
		{"True", true, true},
		{"  true  ", true, true},
		// Anything that isn't one of the accepted forms is an error —
		// including the common "false"/"0"/"no" footguns.
		{"0", false, false},
		{"false", false, false},
		{"FALSE", false, false},
		{"no", false, false},
		{"off", false, false},
		{"disabled", false, false},
		{"yes", false, false},
		{"ture", false, false},
		{"1 0", false, false},
		{"garbage", false, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			parsed, ok := ParseBoolExplicit(tc.in)
			if parsed != tc.wantParsed || ok != tc.wantOK {
				t.Fatalf("ParseBoolExplicit(%q) = (%v, %v); want (%v, %v)",
					tc.in, parsed, ok, tc.wantParsed, tc.wantOK)
			}
		})
	}
}

func TestInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if !InProduction() {
		t.Fatal("ENVIRONMENT=production must be in production")
	}
	t.Setenv("ENVIRONMENT", "development")
	if InProduction() {
		t.Fatal("ENVIRONMENT=development must not be in production")
	}
}

func TestRequireHex(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if err := RequireHex("K", "", 32); err == nil {
		t.Fatal("empty must fail in prod")
	}
	if err := RequireHex("K", "not-hex!!", 32); err == nil {
		t.Fatal("non-hex must fail in prod")
	}
	if err := RequireHex("K", "ab", 32); err == nil {
		t.Fatal("too-short hex must fail in prod")
	}
	if err := RequireHex("K", strings.Repeat("ab", 32), 32); err != nil {
		t.Fatalf("valid hex must pass: %v", err)
	}
	t.Setenv("ENVIRONMENT", "development")
	if err := RequireHex("K", "", 32); err != nil {
		t.Fatalf("dev should be permissive: %v", err)
	}
}

func TestRequireNonEmpty(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if err := RequireNonEmpty("X", "  "); err == nil {
		t.Fatal("blank must fail in prod")
	}
	if err := RequireNonEmpty("X", "x"); err != nil {
		t.Fatalf("non-empty must pass: %v", err)
	}
}

func TestRequireEnum(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if err := RequireEnum("M", "vsock", "vsock"); err != nil {
		t.Fatalf("matching value must pass: %v", err)
	}
	if err := RequireEnum("M", "http", "vsock"); err == nil {
		t.Fatal("non-matching must fail")
	}
}

func TestRequirePGURLSSL(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if err := RequirePGURLSSL("postgres://u@h/db?sslmode=disable"); err == nil {
		t.Fatal("sslmode=disable must fail in prod")
	}
	if err := RequirePGURLSSL("postgres://u@h/db?sslmode=require"); err != nil {
		t.Fatalf("require must pass: %v", err)
	}
	if err := RequirePGURLSSL(""); err == nil {
		t.Fatal("empty must fail in prod")
	}
}

func TestRequireRediss(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if err := RequireRediss(""); err != nil {
		t.Fatalf("empty redis must pass: %v", err)
	}
	if err := RequireRediss("redis://cache:6379"); err == nil {
		t.Fatal("redis:// must fail in prod")
	}
	if err := RequireRediss("rediss://cache:6380"); err != nil {
		t.Fatalf("rediss:// must pass: %v", err)
	}
}

func TestRequireStrict(t *testing.T) {
	cases := []struct {
		env        string
		wantStrict bool
		wantErr    bool
	}{
		{"", true, false},
		{"1", false, false},
		{"true", false, false},
		{"TRUE", false, false},
		// Any unrecognised value is a hard error — no silent bypass.
		{"false", false, true},
		{"0", false, true},
		{"no", false, true},
		{"off", false, true},
		{"yes", false, true},
		{"disabled", false, true},
		{"garbage", false, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("TEST_STRICT_GATE", tc.env)
			strict, err := RequireStrict("TEST_STRICT_GATE")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("RequireStrict(%q) = (%v, nil); want error", tc.env, strict)
				}
				if !strings.Contains(err.Error(), "TEST_STRICT_GATE") {
					t.Fatalf("error must name env key, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RequireStrict(%q) unexpected error: %v", tc.env, err)
			}
			if strict != tc.wantStrict {
				t.Fatalf("RequireStrict(%q) = %v; want %v", tc.env, strict, tc.wantStrict)
			}
		})
	}
}
