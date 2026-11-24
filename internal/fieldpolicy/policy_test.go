package fieldpolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testPolicy = `{
  "redact": ["email"],
  "bases": {
    "appPeople": {
      "tables": {
        "Contacts": {
          "hidden_fields": ["SSN", "fldSalary"],
          "redact": {"Notes": ["phone", "ssn"], "*": ["ip_address"]}
        },
        "tblContacts": {"redact": {"fldBio": ["full"]}}
      }
    }
  }
}`

func TestParseRejectsMistakesThatWouldExposeFields(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		{"misspelled key", `{"bases":{"appA":{"tables":{"T":{"hidden_field":["SSN"]}}}}}`, "unknown field"},
		{"unknown detector", `{"redact":["emails"]}`, `unknown detector "emails"`},
		{"base name instead of ID", `{"bases":{"People":{"tables":{}}}}`, "must be an Airtable base ID"},
		{"wildcard hidden field", `{"bases":{"appA":{"tables":{"T":{"hidden_fields":["*"]}}}}}`, "must name a field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestTablePolicyMatchesByIDOrCaseInsensitiveName(t *testing.T) {
	policy, err := Parse([]byte(testPolicy))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	// Both the "Contacts" (by name) and "tblContacts" (by ID) entries apply.
	table := policy.Table("appPeople", "tblContacts", "contacts")
	if !table.Hidden("fldSSNid", "ssn") || !table.Hidden("fldSalary", "Annual Salary") {
		t.Fatal("expected SSN (by name) and Salary (by ID) to be hidden")
	}
	if table.Hidden("fldName", "Name") {
		t.Fatal("Name must stay visible")
	}
	if got, want := table.Detectors("fldNotes", "Notes"), DetectEmail|DetectPhone|DetectSSN|DetectIPAddress; got != want {
		t.Fatalf("Notes detectors = %b, want global + * + field rule %b", got, want)
	}
	if got := table.Detectors("fldBio", "Bio"); got&DetectFull == 0 {
		t.Fatalf("Bio detectors = %b, want the ID-keyed full rule", got)
	}
	if !table.HasFieldRule("fldNotes", "Notes") || table.HasFieldRule("fldName", "Name") {
		t.Fatal("HasFieldRule must cover field rules only, not the table-wide * rule")
	}

	other := policy.Table("appOther", "tblContacts", "Contacts")
	if other.Configured() || other.Hidden("fldSSN", "SSN") {
		t.Fatal("rules for appPeople must not apply to another base")
	}
	if other.Detectors("fldX", "X") != DetectEmail {
		t.Fatal("global redaction must apply to every base")
	}

	var empty *Policy
	if empty.Table("appPeople", "tblContacts", "Contacts").Hidden("fldSSN", "SSN") || empty.Fingerprint() != "" {
		t.Fatal("the nil policy must hide nothing and have an empty fingerprint")
	}
}

func TestFingerprintIgnoresFormattingAndKeyOrder(t *testing.T) {
	a, _ := Parse([]byte(`{"redact":["email"],"bases":{"appA":{"tables":{"T":{"hidden_fields":["X"]}}}}}`))
	b, _ := Parse([]byte("{\n \"bases\": {\"appA\": {\"tables\": {\"T\": {\"hidden_fields\": [\"X\"]}}}},\n \"redact\": [\"email\"]\n}"))
	c, _ := Parse([]byte(`{"redact":["email"],"bases":{"appA":{"tables":{"T":{"hidden_fields":["Y"]}}}}}`))
	if a.Fingerprint() == "" || a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("equal policies must share a fingerprint: %q vs %q", a.Fingerprint(), b.Fingerprint())
	}
	if a.Fingerprint() == c.Fingerprint() {
		t.Fatal("a different hidden field must change the fingerprint")
	}
	if empty, err := Parse([]byte(`{}`)); err != nil || empty.Fingerprint() != "" {
		t.Fatalf("an empty document must be the empty policy, got %v / %q", err, empty.Fingerprint())
	}
}

func TestLoadAcceptsInlineJSONOrFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := Load(path)
	if err != nil {
		t.Fatalf("Load(file) returned error: %v", err)
	}
	inline, err := Load(testPolicy)
	if err != nil {
		t.Fatalf("Load(inline) returned error: %v", err)
	}
	if fromFile.Fingerprint() != inline.Fingerprint() {
		t.Fatal("file and inline forms of one policy must be equal")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing policy file must be an error, not an empty policy")
	}
}

func TestUnmatchedKeysReportsTyposAndRenames(t *testing.T) {
	policy, _ := Parse([]byte(`{"bases":{"appA":{"tables":{
		"Contacts": {"hidden_fields": ["SSN", "Socail"], "redact": {"Notes": ["email"], "*": ["phone"]}},
		"Ghost": {"hidden_fields": ["X"]}
	}}}}`))
	got := policy.UnmatchedKeys("appA", []TableRef{{
		ID: "tblContacts", Name: "Contacts",
		Fields: []FieldRef{{ID: "fldSSN", Name: "SSN"}, {ID: "fldNotes", Name: "Notes"}},
	}})
	want := []string{"Contacts/Socail", "Ghost"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnmatchedKeys() = %v, want %v", got, want)
	}
}

func TestResolveHidesComputedFieldsThatReadHiddenOrSchemaOnlyData(t *testing.T) {
	policy, err := Parse([]byte(`{"bases":{"appA":{"tables":{
		"People":  {"hidden_fields": ["SSN"], "redact": {"Email": ["email"], "Bio": ["full"]}},
		"Payroll": {"schema_only": true}
	}}}}`))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}
	resolved := policy.Resolve("appA", []TableRef{
		{ID: "tblPeople", Name: "People", Fields: []FieldRef{
			{ID: "fldSSN", Name: "SSN"},
			{ID: "fldEmail", Name: "Email"},
			{ID: "fldBio", Name: "Bio"},
			{ID: "fldLast4", Name: "SSN last 4", References: []string{"fldSSN"}},
			// Declared before the field it reads, so one pass is not enough.
			{ID: "fldMasked", Name: "Masked", References: []string{"fldLast4b"}},
			{ID: "fldLast4b", Name: "Last 4 again", References: []string{"fldLast4"}},
			{ID: "fldContact", Name: "Contact", References: []string{"fldEmail", "fldBio"}},
			{ID: "fldPayLink", Name: "Payroll", References: nil},
			{ID: "fldSalary", Name: "Salary (lookup)", References: []string{"fldPayLink", "fldAmount"}},
			{ID: "fldPayCount", Name: "Payslips", References: []string{"fldPayLink"}},
		}},
		{ID: "tblPayroll", Name: "Payroll", Fields: []FieldRef{
			{ID: "fldAmount", Name: "Amount"},
			{ID: "fldDouble", Name: "Double", References: []string{"fldAmount"}},
		}},
		{ID: "tblOrders", Name: "Orders", Fields: []FieldRef{
			{ID: "fldBuyerSSN", Name: "Buyer SSN", References: []string{"fldBuyer", "fldSSN"}},
			{ID: "fldBuyerEmail", Name: "Buyer email", References: []string{"fldBuyer", "fldEmail"}},
		}},
	})

	for _, id := range []string{"fldSSN", "fldLast4", "fldLast4b", "fldMasked", "fldSalary", "fldBuyerSSN"} {
		if !resolved.Hidden(id) {
			t.Errorf("%s should be hidden", id)
		}
	}
	for _, id := range []string{"fldEmail", "fldContact", "fldPayLink", "fldPayCount", "fldAmount", "fldDouble", "fldBuyerEmail"} {
		if resolved.Hidden(id) {
			t.Errorf("%s should stay visible", id)
		}
	}
	if got := resolved.Detectors("fldContact"); got != DetectEmail|DetectFull {
		t.Errorf("Contact detectors = %b, want inherited email|full", got)
	}
	if got := resolved.Detectors("fldBuyerEmail"); got != DetectEmail {
		t.Errorf("a lookup of a redacted field in another table must inherit it, got %b", got)
	}
	if !resolved.SchemaOnly("tblPayroll") || resolved.SchemaOnly("tblPeople") {
		t.Error("only Payroll is schema-only")
	}
}

func TestBaseLevelSchemaOnly(t *testing.T) {
	policy, err := Parse([]byte(`{"bases":{"appA":{"schema_only":true}}}`))
	if err != nil || policy == nil {
		t.Fatalf("a base-level schema_only policy must not be empty: %v", err)
	}
	table := policy.Table("appA", "tblAny", "Any")
	if !table.SchemaOnly() || table.Configured() {
		t.Fatal("every table of the base is schema-only, without counting as a name-keyed table rule")
	}
	if policy.Table("appB", "tblAny", "Any").SchemaOnly() {
		t.Fatal("schema_only must not leak to other bases")
	}
}
