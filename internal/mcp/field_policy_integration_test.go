//go:build integration

package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/hackclub/better-airtable-mcp/internal/approval"
	"github.com/hackclub/better-airtable-mcp/internal/config"
	"github.com/hackclub/better-airtable-mcp/internal/cryptoutil"
	"github.com/hackclub/better-airtable-mcp/internal/db"
	"github.com/hackclub/better-airtable-mcp/internal/fieldpolicy"
	"github.com/hackclub/better-airtable-mcp/internal/mcp"
	"github.com/hackclub/better-airtable-mcp/internal/oauth"
	syncer "github.com/hackclub/better-airtable-mcp/internal/sync"
	"github.com/hackclub/better-airtable-mcp/internal/tools"
)

const fieldPolicyTestDoc = `{
  "redact": ["email"],
  "bases": {"appPeople": {"tables": {"Contacts": {
    "hidden_fields": ["SSN", "fldSalary"],
    "redact": {"Notes": ["all"], "Bio": ["full"]}
  }}}}
}`

// Values that must never reach the agent through any tool.
var fieldPolicySecrets = []string{"123-45-6789", "120000", "ada@example.com", "555-123-4567", "4111 1111 1111 1111", "Analytical Way", "SSN", "ssn", "Salary", "salary"}

func TestFieldPolicyGatesAndRedactsEveryToolOverMCP(t *testing.T) {
	port := mutateFreePort(t)
	postgres := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Port(uint32(port)).
			Database("better_airtable_field_policy_test").
			Username("postgres").
			Password("postgres").
			BinariesPath(filepath.Join(t.TempDir(), "postgres-binaries")).
			DataPath(filepath.Join(t.TempDir(), "postgres-data")).
			RuntimePath(filepath.Join(t.TempDir(), "postgres-runtime")),
	)
	if err := postgres.Start(); err != nil {
		t.Fatalf("embedded postgres start failed: %v", err)
	}
	defer postgres.Stop()

	store, err := db.Open(context.Background(), fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/better_airtable_field_policy_test?sslmode=disable", port))
	if err != nil {
		t.Fatalf("db.Open() returned error: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("store.Migrate() returned error: %v", err)
	}

	fakeAirtable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v0/meta/bases":
			writeMCPJSON(t, w, map[string]any{
				"bases": []map[string]any{{"id": "appPeople", "name": "People", "permissionLevel": "create"}},
			})
		case r.URL.Path == "/v0/meta/bases/appPeople/tables" && r.Method == http.MethodGet:
			writeMCPJSON(t, w, map[string]any{"tables": []map[string]any{{
				"id":   "tblContacts",
				"name": "Contacts",
				"fields": []map[string]any{
					{"id": "fldName", "name": "Name", "type": "singleLineText"},
					{"id": "fldEmail", "name": "Email", "type": "email"},
					{"id": "fldSSN", "name": "SSN", "type": "singleLineText"},
					{"id": "fldSalary", "name": "Salary", "type": "currency"},
					{"id": "fldNotes", "name": "Notes", "type": "multilineText"},
					{"id": "fldBio", "name": "Bio", "type": "multilineText"},
				},
			}}})
		case r.URL.Path == "/v0/appPeople/tblContacts" && r.Method == http.MethodGet:
			writeMCPJSON(t, w, map[string]any{"records": []map[string]any{{
				"id":          "recAda",
				"createdTime": "2026-04-01T12:00:00Z",
				"fields": map[string]any{
					"Name":   "Ada Lovelace",
					"Email":  "ada@example.com",
					"SSN":    "123-45-6789",
					"Salary": 120000,
					"Notes":  "Call 555-123-4567 or ada@example.com; card 4111 1111 1111 1111",
					"Bio":    "Lives at 12 Analytical Way",
				},
			}}})
		default:
			t.Errorf("unexpected Airtable %s %s", r.Method, r.URL.Path)
		}
	}))
	defer fakeAirtable.Close()

	secret, err := cryptoutil.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("cryptoutil.New() returned error: %v", err)
	}
	if err := store.UpsertUser(context.Background(), db.User{ID: "user_1"}); err != nil {
		t.Fatalf("store.UpsertUser() returned error: %v", err)
	}
	encryptedToken, err := secret.Encrypt([]byte("airtable-access-token"))
	if err != nil {
		t.Fatalf("secret.Encrypt() returned error: %v", err)
	}
	if err := store.PutAirtableToken(context.Background(), db.AirtableTokenRecord{
		UserID:                 "user_1",
		AccessTokenCiphertext:  encryptedToken,
		RefreshTokenCiphertext: encryptedToken,
		ExpiresAt:              time.Now().Add(time.Hour),
		Scopes:                 "data.records:read data.records:write schema.bases:read schema.bases:write",
	}); err != nil {
		t.Fatalf("store.PutAirtableToken() returned error: %v", err)
	}
	bearerToken := "mcp-access-token"
	if err := store.PutMCPToken(context.Background(), db.MCPTokenRecord{
		TokenHash: oauth.HashToken(bearerToken),
		UserID:    "user_1",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}); err != nil {
		t.Fatalf("store.PutMCPToken() returned error: %v", err)
	}

	policy, err := fieldpolicy.Parse([]byte(fieldPolicyTestDoc))
	if err != nil {
		t.Fatalf("fieldpolicy.Parse() returned error: %v", err)
	}
	cfg := config.Config{
		BaseURL:           mustParseTestURL(t, "http://example.test"),
		SyncInterval:      time.Minute,
		SyncTTL:           10 * time.Minute,
		ApprovalTTL:       60 * time.Minute,
		QueryDefaultLimit: 100,
		QueryMaxLimit:     1000,
		FieldPolicy:       policy,
	}
	dataDir := t.TempDir()
	syncService := syncer.NewService(syncer.NewHTTPClient(fakeAirtable.URL, fakeAirtable.Client()), dataDir)
	syncService.SetFieldPolicy(cfg.FieldPolicy)
	runtime := &tools.Runtime{Store: store, Cipher: secret, Syncer: syncService, Config: cfg}
	syncManager := syncer.NewManager(syncService, store, runtime, cfg.SyncInterval, cfg.SyncTTL)
	runtime.SyncManager = syncManager
	runtime.Approval = approval.NewService(store, secret, syncService, syncManager, runtime, syncer.NewHTTPClient(fakeAirtable.URL, fakeAirtable.Client()), cfg.BaseURLString(), cfg.ApprovalTTL)
	handler := oauth.NewMiddleware(store, "").RequireBearer(mcp.NewHandler("better-airtable-mcp", "0.1.0", tools.NewCatalog(cfg, runtime)))

	ensureBaseSyncedForMutationTest(t, runtime, "user_1", "People")

	call := func(tool string, arguments map[string]any) string {
		t.Helper()
		response := performAuthenticatedToolCall(t, handler, bearerToken, tool, arguments)
		raw, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json.Marshal() returned error: %v", err)
		}
		return string(raw)
	}
	assertNoSecrets := func(label, text string) {
		t.Helper()
		for _, value := range fieldPolicySecrets {
			if strings.Contains(text, value) {
				t.Fatalf("%s leaked %q: %s", label, value, text)
			}
		}
	}
	update := func(fields map[string]any) string {
		return call("mutate", map[string]any{
			"base": "People",
			"operations": []map[string]any{{
				"type":    "update_records",
				"table":   "contacts",
				"records": []map[string]any{{"id": "recAda", "fields": fields}},
			}},
		})
	}
	schemaChange := func(operation map[string]any) string {
		return call("manage_schema", map[string]any{"base": "People", "operations": []map[string]any{operation}})
	}

	// Reads: list_schema samples and SELECT * show only visible, redacted data.
	schemaText := call("list_schema", map[string]any{"base": "People"})
	assertNoSecrets("list_schema", schemaText)
	if !strings.Contains(schemaText, "id,created_time,name,email,notes,bio") {
		t.Fatalf("list_schema should list exactly the visible columns, got %s", schemaText)
	}

	selectAll := call("query", map[string]any{"base": "People", "sql": []string{"SELECT * FROM contacts", "SELECT * FROM _metadata"}})
	assertNoSecrets("SELECT *", selectAll)
	for _, want := range []string{
		"[REDACTED_EMAIL]",
		"Call [REDACTED_PHONE] or [REDACTED_EMAIL]; card [REDACTED_CREDIT_CARD]",
		`"[REDACTED]"`,
		"Ada Lovelace",
	} {
		if !strings.Contains(selectAll, want) {
			t.Fatalf("SELECT * should contain %q, got %s", want, selectAll)
		}
	}
	for _, sql := range []string{"SELECT ssn FROM contacts", `SELECT "SSN" FROM contacts`, "SELECT salary FROM contacts"} {
		named := call("query", map[string]any{"base": "People", "sql": []string{sql}})
		if !strings.Contains(named, "not found") && !strings.Contains(named, "does not have a column") {
			t.Fatalf("%s should fail with a missing-column error, got %s", sql, named)
		}
	}

	// Writes: hidden fields cannot be resolved by column, original name, or ID.
	for _, field := range []string{"ssn", "SSN", "fldSSN", "salary", "fldSalary"} {
		result := update(map[string]any{field: "x"})
		if !strings.Contains(result, "unknown field") {
			t.Fatalf("mutate on hidden field %q should be an unknown field, got %s", field, result)
		}
		assertNoSecrets("mutate error", strings.ReplaceAll(result, field, ""))
	}
	if result := update(map[string]any{"notes": "Call [REDACTED_PHONE] tomorrow"}); !strings.Contains(result, "redaction placeholder") {
		t.Fatalf("writing a redaction placeholder back should be refused, got %s", result)
	}
	if result := update(map[string]any{"notes": "Call tomorrow"}); !strings.Contains(result, "pending_approval") {
		t.Fatalf("an ordinary update to a redacted field should still be allowed, got %s", result)
	}

	// Schema: hidden fields cannot be found, and policy-covered names cannot be renamed.
	if result := schemaChange(map[string]any{"type": "update_field", "table": "Contacts", "field": "SSN", "name": "Tax ID"}); !strings.Contains(result, "unknown field") {
		t.Fatalf("manage_schema on a hidden field should be an unknown field, got %s", result)
	}
	if result := schemaChange(map[string]any{"type": "update_field", "table": "Contacts", "field": "Notes", "name": "Remarks"}); !strings.Contains(result, "field policy") {
		t.Fatalf("renaming a redacted field should be refused, got %s", result)
	}
	if result := schemaChange(map[string]any{"type": "update_table", "table": "Contacts", "name": "People"}); !strings.Contains(result, "field policy") {
		t.Fatalf("renaming a policy-covered table should be refused, got %s", result)
	}
	if result := schemaChange(map[string]any{"type": "update_field", "table": "Contacts", "field": "Notes", "description": "Free text"}); !strings.Contains(result, "pending_approval") {
		t.Fatalf("a description-only edit should still be allowed, got %s", result)
	}
	if result := schemaChange(map[string]any{"type": "update_field", "table": "Contacts", "field": "Name", "name": "Full Name"}); !strings.Contains(result, "pending_approval") {
		t.Fatalf("renaming a field the policy does not name should still be allowed, got %s", result)
	}

	// Restart: a cache built under another policy is dropped; the same policy keeps it.
	cachePath := syncService.DatabasePath("appPeople")
	samePolicy := syncer.NewService(syncer.NewHTTPClient(fakeAirtable.URL, fakeAirtable.Client()), dataDir)
	samePolicy.SetFieldPolicy(policy)
	if err := syncer.NewManager(samePolicy, store, runtime, cfg.SyncInterval, cfg.SyncTTL).SweepStaleDuckDBFiles(context.Background()); err != nil {
		t.Fatalf("SweepStaleDuckDBFiles() returned error: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("a cache built under the current policy must survive the sweep: %v", err)
	}
	noPolicy := syncer.NewService(syncer.NewHTTPClient(fakeAirtable.URL, fakeAirtable.Client()), dataDir)
	if err := syncer.NewManager(noPolicy, store, runtime, cfg.SyncInterval, cfg.SyncTTL).SweepStaleDuckDBFiles(context.Background()); err != nil {
		t.Fatalf("SweepStaleDuckDBFiles() returned error: %v", err)
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("a cache built under a different policy must be removed, stat err = %v", err)
	}
}
