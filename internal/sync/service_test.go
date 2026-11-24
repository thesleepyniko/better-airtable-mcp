package syncer

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hackclub/better-airtable-mcp/internal/duckdb"
	"github.com/hackclub/better-airtable-mcp/internal/fieldpolicy"
)

func TestBuildSyncPlansDisambiguatesDuplicateFieldNames(t *testing.T) {
	tables := []Table{{
		ID:   "tbl1",
		Name: "Tasks",
		Fields: []Field{
			{ID: "fld1", Name: "Status", Type: "singleLineText"},
			{ID: "fld2", Name: "Status", Type: "singleLineText"},
		},
	}}

	plans, err := buildSyncPlans("appTest", tables, nil)
	if err != nil {
		t.Fatalf("buildSyncPlans() returned error: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}

	fields := plans[0].Table.Fields
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d (%#v)", len(fields), fields)
	}

	if fields[0].AirtableFieldID != "fld1" || fields[1].AirtableFieldID != "fld2" {
		t.Fatalf("field order not preserved: got %q, %q", fields[0].AirtableFieldID, fields[1].AirtableFieldID)
	}
	if fields[0].DuckDBColumnName == fields[1].DuckDBColumnName {
		t.Fatalf("duplicate field names collapsed to the same column %q", fields[0].DuckDBColumnName)
	}
	if got := fields[0].DuckDBColumnName; got != "status" {
		t.Fatalf("field fld1: want column %q, got %q", "status", got)
	}
	if got := fields[1].DuckDBColumnName; got != "status_2" {
		t.Fatalf("field fld2: want column %q, got %q", "status_2", got)
	}
}

func TestBuildSyncPlansKeepsSanitizedIndexAlignedAcrossOmittedFields(t *testing.T) {
	// "button" maps to an omitted DuckDB type, so it is dropped from the synced
	// fields. The sanitized-name index must skip it without drifting, otherwise
	// the fields straddling the omission get the wrong columns.
	tables := []Table{{
		ID:   "tbl1",
		Name: "Tasks",
		Fields: []Field{
			{ID: "fld1", Name: "Status", Type: "singleLineText"},
			{ID: "fldBtn", Name: "Open", Type: "button"},
			{ID: "fld2", Name: "Status", Type: "singleLineText"},
		},
	}}

	plans, err := buildSyncPlans("appTest", tables, nil)
	if err != nil {
		t.Fatalf("buildSyncPlans() returned error: %v", err)
	}

	fields := plans[0].Table.Fields
	if len(fields) != 2 {
		t.Fatalf("expected the omitted button field to be dropped, got %d fields (%#v)", len(fields), fields)
	}

	want := map[string]string{
		"fld1": "status",
		"fld2": "status_2",
	}
	for _, field := range fields {
		if got := field.DuckDBColumnName; got != want[field.AirtableFieldID] {
			t.Fatalf("field %s: want column %q, got %q", field.AirtableFieldID, want[field.AirtableFieldID], got)
		}
	}
}

type countingBasesClient struct {
	listBasesCalls atomic.Int32
	bases          []Base
}

func (c *countingBasesClient) ListBases(ctx context.Context, accessToken string) ([]Base, error) {
	c.listBasesCalls.Add(1)
	return c.bases, nil
}

func (c *countingBasesClient) GetBaseSchema(ctx context.Context, accessToken, baseID string) ([]Table, error) {
	return nil, nil
}

func (c *countingBasesClient) ListRecordsPage(ctx context.Context, accessToken, baseID, tableID string, options ListRecordsPageOptions) (ListRecordsPageResult, error) {
	return ListRecordsPageResult{}, nil
}

func (c *countingBasesClient) ListRecords(ctx context.Context, accessToken, baseID, tableID string) ([]Record, error) {
	return nil, nil
}

func TestResolveBaseCachesBaseListPerToken(t *testing.T) {
	client := &countingBasesClient{bases: []Base{
		{ID: "appProjects", Name: "Project Tracker", PermissionLevel: "create"},
		{ID: "appOther", Name: "Other Base", PermissionLevel: "read"},
	}}
	service := NewService(client, t.TempDir())

	current := time.Now()
	service.now = func() time.Time { return current }

	for _, ref := range []string{"appProjects", "Project Tracker", "project"} {
		base, err := service.resolveBase(context.Background(), "token-a", ref)
		if err != nil {
			t.Fatalf("resolveBase(%q) returned error: %v", ref, err)
		}
		if base.ID != "appProjects" {
			t.Fatalf("resolveBase(%q) = %#v, want appProjects", ref, base)
		}
	}
	if got := client.listBasesCalls.Load(); got != 1 {
		t.Fatalf("expected one ListBases call within the cache TTL, got %d", got)
	}

	// A different token must not share the cache entry.
	if _, err := service.resolveBase(context.Background(), "token-b", "appProjects"); err != nil {
		t.Fatalf("resolveBase() with second token returned error: %v", err)
	}
	if got := client.listBasesCalls.Load(); got != 2 {
		t.Fatalf("expected a fresh ListBases call for a new token, got %d", got)
	}

	// Past the TTL the list is re-fetched.
	current = current.Add(baseListCacheTTL + time.Second)
	if _, err := service.resolveBase(context.Background(), "token-a", "appProjects"); err != nil {
		t.Fatalf("resolveBase() after TTL returned error: %v", err)
	}
	if got := client.listBasesCalls.Load(); got != 3 {
		t.Fatalf("expected a refreshed ListBases call after the TTL, got %d", got)
	}
}

type policyTestClient struct {
	countingBasesClient
}

func (c *policyTestClient) GetBaseSchema(ctx context.Context, accessToken, baseID string) ([]Table, error) {
	return []Table{{
		ID:   "tblContacts",
		Name: "Contacts",
		Fields: []Field{
			{ID: "fldName", Name: "Name", Type: "singleLineText"},
			// Sanitizes to "name" too; with the visible Name it would have
			// been "name_2", so hiding it must not leave a gap in the names.
			{ID: "fldName2", Name: "NAME", Type: "singleLineText"},
			{ID: "fldSSN", Name: "SSN", Type: "singleLineText"},
			{ID: "fldSalary", Name: "Salary", Type: "currency"},
			{ID: "fldNotes", Name: "Notes", Type: "multilineText"},
			{ID: "fldScore", Name: "Score", Type: "number"},
			{ID: "fldTags", Name: "Tags", Type: "lookup", Options: map[string]any{"recordLinkFieldId": "fldOtherLink", "fieldIdInLinkedTable": "fldOther"}},
			{ID: "fldOpaque", Name: "Opaque", Type: "formula"},
		},
	}}, nil
}

func (c *policyTestClient) ListRecordsPage(ctx context.Context, accessToken, baseID, tableID string, options ListRecordsPageOptions) (ListRecordsPageResult, error) {
	return ListRecordsPageResult{Records: []Record{{
		ID:          "recAda",
		CreatedTime: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		Fields: map[string]any{
			"Name":   "Ada",
			"NAME":   "secret alias",
			"SSN":    "123-45-6789",
			"Salary": 120000.0,
			"Notes":  "call 555-123-4567 or ada@example.com",
			"Score":  5551234567.0,
			"Tags":   []any{"ops@example.com", "vip"},
		},
	}}}, nil
}

func TestSyncKeepsHiddenFieldsAndRawPIIOutOfTheCache(t *testing.T) {
	policy, err := fieldpolicy.Parse([]byte(`{
		"redact": ["email"],
		"bases": {"appPeople": {"tables": {"Contacts": {
			"hidden_fields": ["SSN", "fldSalary", "fldName2"],
			"redact": {"Notes": ["phone"], "Score": ["phone"]}
		}}}}
	}`))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}
	client := &policyTestClient{countingBasesClient{bases: []Base{{ID: "appPeople", Name: "People"}}}}
	service := NewService(client, t.TempDir())
	service.SetFieldPolicy(policy)
	ctx := context.Background()
	if _, err := service.SyncBase(ctx, "token", "appPeople"); err != nil {
		t.Fatalf("SyncBase() returned error: %v", err)
	}

	result, err := service.QueryResolvedBase(ctx, "appPeople", "SELECT * FROM contacts")
	if err != nil {
		t.Fatalf("SELECT * returned error: %v", err)
	}
	// Opaque is a formula with no options, so its inputs are unknown: hidden.
	wantColumns := []string{"id", "created_time", "name", "notes", "score", "tags"}
	if !reflect.DeepEqual(result.Columns, wantColumns) {
		t.Fatalf("SELECT * columns = %v, want %v", result.Columns, wantColumns)
	}
	row := map[string]any{}
	for index, column := range result.Columns {
		row[column] = result.Rows[0][index]
	}
	if row["notes"] != "call [REDACTED_PHONE] or [REDACTED_EMAIL]" {
		t.Fatalf("notes = %#v, want phone and email redacted", row["notes"])
	}
	if row["score"] != 5551234567.0 {
		t.Fatalf("score = %#v, want numbers left alone by pattern detectors", row["score"])
	}
	if tags := fmt.Sprint(row["tags"]); !strings.Contains(tags, "[REDACTED_EMAIL]") || strings.Contains(tags, "ops@example.com") {
		t.Fatalf("tags = %s, want the email inside the lookup redacted", tags)
	}

	for _, query := range []string{
		"SELECT ssn FROM contacts",
		"SELECT salary FROM contacts",
		"SELECT name_2 FROM contacts",
	} {
		if _, err := service.QueryResolvedBase(ctx, "appPeople", query); err == nil {
			t.Fatalf("%s succeeded; hidden fields must have no column", query)
		}
	}
	metadata, err := service.QueryResolvedBase(ctx, "appPeople", "SELECT * FROM _metadata")
	if err != nil {
		t.Fatalf("SELECT * FROM _metadata returned error: %v", err)
	}
	if dump := fmt.Sprint(metadata.Rows); strings.Contains(dump, "SSN") || strings.Contains(dump, "Salary") || strings.Contains(dump, "fldName2") {
		t.Fatalf("_metadata mentions a hidden field: %s", dump)
	}

	fingerprint, err := duckdb.ReadFieldPolicyFingerprint(ctx, service.DatabasePath("appPeople"))
	if err != nil || fingerprint != policy.Fingerprint() {
		t.Fatalf("cache fingerprint = %q (%v), want %q", fingerprint, err, policy.Fingerprint())
	}
}

type derivedPolicyClient struct {
	countingBasesClient
	mu           sync.Mutex
	fetchedPages map[string]int
}

func (c *derivedPolicyClient) GetBaseSchema(ctx context.Context, accessToken, baseID string) ([]Table, error) {
	return []Table{
		{ID: "tblPeople", Name: "People", Fields: []Field{
			{ID: "fldName", Name: "Name", Type: "singleLineText"},
			{ID: "fldSSN", Name: "SSN", Type: "singleLineText"},
			{ID: "fldEmail", Name: "Email", Type: "email"},
			{ID: "fldLast4", Name: "SSN Last 4", Type: "formula", Options: map[string]any{"referencedFieldIds": []any{"fldSSN"}}},
			{ID: "fldGreeting", Name: "Greeting", Type: "formula", Options: map[string]any{"referencedFieldIds": []any{"fldName", "fldEmail"}}},
			{ID: "fldPay", Name: "Payslips", Type: "multipleRecordLinks", Options: map[string]any{"linkedTableId": "tblPayroll"}},
			{ID: "fldTotalPay", Name: "Total Pay", Type: "rollup", Options: map[string]any{"recordLinkFieldId": "fldPay", "fieldIdInLinkedTable": "fldAmount", "referencedFieldIds": []any{}}},
		}},
		{ID: "tblPayroll", Name: "Payroll", Fields: []Field{
			{ID: "fldAmount", Name: "Amount", Type: "currency"},
			{ID: "fldPerson", Name: "Person", Type: "multipleRecordLinks", Options: map[string]any{"linkedTableId": "tblPeople"}},
		}},
	}, nil
}

func (c *derivedPolicyClient) ListRecordsPage(ctx context.Context, accessToken, baseID, tableID string, options ListRecordsPageOptions) (ListRecordsPageResult, error) {
	c.mu.Lock()
	c.fetchedPages[tableID]++
	c.mu.Unlock()
	if tableID == "tblPayroll" {
		return ListRecordsPageResult{Records: []Record{{ID: "recPay1", Fields: map[string]any{"Amount": 9000.0, "Person": []any{"recAda"}}}}}, nil
	}
	return ListRecordsPageResult{Records: []Record{{
		ID:          "recAda",
		CreatedTime: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		Fields: map[string]any{
			"Name":       "Ada",
			"SSN":        "123-45-6789",
			"Email":      "ada@example.com",
			"SSN Last 4": "6789",
			"Greeting":   "Hi Ada <ada@example.com>",
			"Payslips":   []any{"recPay1"},
			"Total Pay":  9000.0,
		},
	}}}, nil
}

func TestSyncHidesDerivedFieldsAndWithholdsSchemaOnlyTables(t *testing.T) {
	policy, err := fieldpolicy.Parse([]byte(`{"bases": {"appPeople": {"tables": {
		"People":  {"hidden_fields": ["SSN"], "redact": {"Email": ["email"]}},
		"Payroll": {"schema_only": true}
	}}}}`))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}
	client := &derivedPolicyClient{
		countingBasesClient: countingBasesClient{bases: []Base{{ID: "appPeople", Name: "People"}}},
		fetchedPages:        map[string]int{},
	}
	service := NewService(client, t.TempDir())
	service.SetFieldPolicy(policy)
	ctx := context.Background()
	var last SyncProgress
	if _, err := service.runSync(ctx, StaticAccessToken("token"), Base{ID: "appPeople", Name: "People"}, func(p SyncProgress) { last = p }); err != nil {
		t.Fatalf("runSync() returned error: %v", err)
	}
	if last.Status != "completed" || last.TablesCompleted != 2 {
		t.Fatalf("expected a completed run counting the schema-only table, got %+v", last)
	}
	if client.fetchedPages["tblPayroll"] != 0 {
		t.Fatalf("schema-only Payroll records were fetched %d times", client.fetchedPages["tblPayroll"])
	}

	people, err := service.QueryResolvedBase(ctx, "appPeople", "SELECT * FROM people")
	if err != nil {
		t.Fatalf("SELECT * FROM people returned error: %v", err)
	}
	if want := []string{"id", "created_time", "name", "email", "greeting"}; !reflect.DeepEqual(people.Columns, want) {
		t.Fatalf("people columns = %v, want %v (formula over SSN, link into schema-only Payroll, and rollup over it hidden)", people.Columns, want)
	}
	if greeting := people.Rows[0][4]; greeting != "[REDACTED]" {
		t.Fatalf("greeting = %#v, want a formula over redacted Email fully redacted", greeting)
	}

	payroll, err := service.QueryResolvedBase(ctx, "appPeople", "SELECT * FROM payroll")
	if err != nil {
		t.Fatalf("SELECT * FROM payroll returned error: %v", err)
	}
	if want := []string{"id", "created_time", "amount", "person"}; !reflect.DeepEqual(payroll.Columns, want) || len(payroll.Rows) != 0 {
		t.Fatalf("payroll = %v with %d rows, want its columns and no rows", payroll.Columns, len(payroll.Rows))
	}
	schema, err := service.ListResolvedSchema(ctx, "appPeople", "People")
	if err != nil {
		t.Fatalf("ListResolvedSchema() returned error: %v", err)
	}
	for _, table := range schema.Tables {
		if table.DuckDBTableName == "payroll" && table.SyncStatus != duckdb.TableSyncSchemaOnly {
			t.Fatalf("payroll sync status = %q, want %q", table.SyncStatus, duckdb.TableSyncSchemaOnly)
		}
	}
}

type renamedFieldClient struct{ policyTestClient }

func (c *renamedFieldClient) GetBaseSchema(ctx context.Context, accessToken, baseID string) ([]Table, error) {
	tables, _ := c.policyTestClient.GetBaseSchema(ctx, accessToken, baseID)
	for index := range tables[0].Fields {
		if tables[0].Fields[index].Name == "SSN" {
			tables[0].Fields[index].Name = "Social Security Number"
		}
	}
	return tables, nil
}

func TestSyncRefusesWhenAPolicyKeyNoLongerMatches(t *testing.T) {
	policy, err := fieldpolicy.Parse([]byte(`{"bases": {"appPeople": {"tables": {"Contacts": {"hidden_fields": ["SSN"]}}}}}`))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}
	client := &renamedFieldClient{policyTestClient{countingBasesClient{bases: []Base{{ID: "appPeople", Name: "People"}}}}}
	service := NewService(client, t.TempDir())
	service.SetFieldPolicy(policy)
	_, err = service.SyncBase(context.Background(), "token", "appPeople")
	if err == nil || !strings.Contains(err.Error(), "field policy") {
		t.Fatalf("a renamed hidden field must stop the sync, got %v", err)
	}
	if strings.Contains(err.Error(), "SSN") {
		t.Fatalf("the agent-facing error must not name the hidden field: %v", err)
	}
	if duckdb.DatabaseFileExists(service.DatabasePath("appPeople")) {
		t.Fatal("no cache may be written while the policy does not match")
	}
}
