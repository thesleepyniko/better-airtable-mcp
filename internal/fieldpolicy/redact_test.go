package fieldpolicy

import (
	"reflect"
	"testing"
)

func TestRedactStringFindsPII(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detectors Detectors
		in, want  string
	}{
		{"email", DetectEmail, "write to ada.l+mcp@mail.example.co.uk today", "write to [REDACTED_EMAIL] today"},
		{"email with digits before phone", detectAllPatterns, "5551234567@example.com", "[REDACTED_EMAIL]"},
		{"us phone formats", DetectPhone, "(555) 123-4567, 555.123.4567, 5551234567", "[REDACTED_PHONE], [REDACTED_PHONE], [REDACTED_PHONE]"},
		{"international phone", DetectPhone, "call +44 20 7946 0958 now", "call [REDACTED_PHONE] now"},
		{"ssn", DetectSSN, "SSN 123-45-6789.", "SSN [REDACTED_SSN]."},
		{"luhn-valid card", DetectCreditCard, "card 4111 1111 1111 1111 ok", "card [REDACTED_CREDIT_CARD] ok"},
		{"ip address", DetectIPAddress, "from 192.168.10.255", "from [REDACTED_IP_ADDRESS]"},
		{"full", DetectFull, "12 Analytical Way, London", "[REDACTED]"},
		{"full keeps empty", DetectFull, "", ""},
		{"only requested detectors run", DetectEmail, "ada@example.com 555-123-4567", "[REDACTED_EMAIL] 555-123-4567"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.detectors.RedactString(tc.in); got != tc.want {
				t.Fatalf("RedactString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactStringLeavesLookalikesAlone(t *testing.T) {
	for _, in := range []string{
		"2026-04-01T12:00:00.000Z",    // timestamps
		"recA1b2C3d4E5f6G7",           // record IDs
		"4111 1111 1111 1112",         // card-shaped but fails Luhn
		"version 1.2.3.4567",          // not an IPv4 address or a phone number
		"order 12345 shipped 3 items", // short numbers
		"999.999.1.1",                 // octets out of range
	} {
		if got := detectAllPatterns.RedactString(in); got != in {
			t.Errorf("RedactString(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestRedactWalksStructuredValues(t *testing.T) {
	lookup := []any{
		"ada@example.com",
		map[string]any{"email": "bob@example.com", "count": 3.0},
		true,
	}
	got := DetectEmail.Redact(lookup, true)
	want := []any{
		"[REDACTED_EMAIL]",
		map[string]any{"email": "[REDACTED_EMAIL]", "count": 3.0},
		true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Redact() = %#v, want %#v", got, want)
	}
	if lookup[0] != "ada@example.com" {
		t.Fatal("Redact must not modify its input")
	}

	if got := DetectFull.Redact(120000.0, false); got != nil {
		t.Fatalf("full redaction of a number column = %#v, want nil", got)
	}
	if got := DetectFull.Redact([]any{"VIP"}, true); got != PlaceholderFull {
		t.Fatalf("full redaction of a text column = %#v, want %q", got, PlaceholderFull)
	}
}

func TestContainsPlaceholder(t *testing.T) {
	if !ContainsPlaceholder(map[string]any{"a": []any{"x", "Call [REDACTED_PHONE]"}}) {
		t.Fatal("expected a nested placeholder to be found")
	}
	if !ContainsPlaceholder("[REDACTED]") {
		t.Fatal("expected the full-redaction placeholder to be found")
	}
	if ContainsPlaceholder("[redacted] by hand, REDACTED_EMAIL") || ContainsPlaceholder(42.0) {
		t.Fatal("only exact placeholders count")
	}
}
