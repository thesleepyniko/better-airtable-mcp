// Package fieldpolicy holds the operator-configured field policy: fields the
// agent must never see or touch (hidden fields) and PII redaction rules for the
// values it reads. The sync applies the policy before anything is written to
// the DuckDB cache, so every read path only ever sees filtered data.
package fieldpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Policy is the parsed FIELD_POLICY. The nil *Policy is the empty policy:
// nothing hidden, nothing redacted.
type Policy struct {
	global      Detectors
	bases       map[string][]tableEntry
	fingerprint string
}

type tableEntry struct {
	key    string
	hidden []string
	redact map[string]Detectors
}

type rawPolicy struct {
	Redact []string           `json:"redact,omitempty"`
	Bases  map[string]rawBase `json:"bases,omitempty"`
}

type rawBase struct {
	Tables map[string]rawTable `json:"tables"`
}

type rawTable struct {
	HiddenFields []string            `json:"hidden_fields,omitempty"`
	Redact       map[string][]string `json:"redact,omitempty"`
}

// Load reads FIELD_POLICY: an inline JSON object, or a path to a JSON file.
// An empty value is the empty policy.
func Load(value string) (*Policy, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	data := []byte(value)
	if !strings.HasPrefix(value, "{") {
		fileData, err := os.ReadFile(value)
		if err != nil {
			return nil, fmt.Errorf("read field policy file: %w", err)
		}
		data = fileData
	}
	return Parse(data)
}

// Parse parses a policy document. Unknown keys and unknown detector names are
// errors, so a typo fails startup instead of silently exposing a field.
func Parse(data []byte) (*Policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw rawPolicy
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse field policy: %w", err)
	}

	policy := &Policy{bases: make(map[string][]tableEntry)}
	global, err := parseDetectors(raw.Redact, "redact")
	if err != nil {
		return nil, err
	}
	policy.global = global

	for baseID, base := range raw.Bases {
		if !strings.HasPrefix(baseID, "app") {
			return nil, fmt.Errorf("field policy: bases key %q must be an Airtable base ID (app...)", baseID)
		}
		for tableKey, table := range base.Tables {
			tableKey = strings.TrimSpace(tableKey)
			if tableKey == "" {
				return nil, fmt.Errorf("field policy: base %s has an empty table key", baseID)
			}
			entry := tableEntry{key: tableKey, redact: make(map[string]Detectors)}
			for _, field := range table.HiddenFields {
				if field = strings.TrimSpace(field); field == "" || field == "*" {
					return nil, fmt.Errorf("field policy: %s/%s hidden_fields entries must name a field", baseID, tableKey)
				}
				entry.hidden = append(entry.hidden, field)
			}
			for fieldKey, names := range table.Redact {
				fieldKey = strings.TrimSpace(fieldKey)
				if fieldKey == "" {
					return nil, fmt.Errorf("field policy: %s/%s has an empty redact field key", baseID, tableKey)
				}
				detectors, err := parseDetectors(names, baseID+"/"+tableKey+" redact."+fieldKey)
				if err != nil {
					return nil, err
				}
				entry.redact[fieldKey] = detectors
			}
			policy.bases[baseID] = append(policy.bases[baseID], entry)
		}
	}

	if policy.global == 0 && len(policy.bases) == 0 {
		return nil, nil
	}

	// encoding/json sorts map keys, so equal policies hash equally.
	canonical, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("fingerprint field policy: %w", err)
	}
	sum := sha256.Sum256(canonical)
	policy.fingerprint = hex.EncodeToString(sum[:])
	return policy, nil
}

// Fingerprint identifies the policy a DuckDB cache was built under. The empty
// policy's fingerprint is "".
func (p *Policy) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.fingerprint
}

// Table returns the rules for one Airtable table. Table keys match the table
// ID or, case-insensitively, its name; every matching entry applies.
func (p *Policy) Table(baseID, tableID, tableName string) TablePolicy {
	if p == nil {
		return TablePolicy{}
	}
	table := TablePolicy{global: p.global}
	for _, entry := range p.bases[baseID] {
		if matchesKey(entry.key, tableID, tableName) {
			table.entries = append(table.entries, entry)
		}
	}
	return table
}

// UnmatchedKeys lists policy keys for baseID that match no table or field in
// the given schema, as "table" or "table/field", so a typo or a rename in
// Airtable can be reported instead of silently leaving a field exposed.
func (p *Policy) UnmatchedKeys(baseID string, tables []TableRef) []string {
	if p == nil {
		return nil
	}
	var unmatched []string
	for _, entry := range p.bases[baseID] {
		var matchedFields []FieldRef
		tableMatched := false
		for _, table := range tables {
			if matchesKey(entry.key, table.ID, table.Name) {
				tableMatched = true
				matchedFields = append(matchedFields, table.Fields...)
			}
		}
		if !tableMatched {
			unmatched = append(unmatched, entry.key)
			continue
		}
		fieldKeys := append([]string(nil), entry.hidden...)
		for key := range entry.redact {
			if key != "*" {
				fieldKeys = append(fieldKeys, key)
			}
		}
		for _, key := range fieldKeys {
			found := false
			for _, field := range matchedFields {
				if matchesKey(key, field.ID, field.Name) {
					found = true
					break
				}
			}
			if !found {
				unmatched = append(unmatched, entry.key+"/"+key)
			}
		}
	}
	sort.Strings(unmatched)
	return unmatched
}

// TableRef and FieldRef describe an Airtable schema for UnmatchedKeys.
type TableRef struct {
	ID     string
	Name   string
	Fields []FieldRef
}

type FieldRef struct {
	ID   string
	Name string
}

// TablePolicy is the policy for one table.
type TablePolicy struct {
	global  Detectors
	entries []tableEntry
}

// Configured reports whether the policy names this table at all.
func (t TablePolicy) Configured() bool {
	return len(t.entries) > 0
}

// Hidden reports whether a field must be excluded from the cache entirely.
func (t TablePolicy) Hidden(fieldID, fieldName string) bool {
	for _, entry := range t.entries {
		for _, key := range entry.hidden {
			if matchesKey(key, fieldID, fieldName) {
				return true
			}
		}
	}
	return false
}

// Detectors returns every redaction detector that applies to a field: the
// global ones, the table's "*" rule, and the field's own rule.
func (t TablePolicy) Detectors(fieldID, fieldName string) Detectors {
	detectors := t.global
	for _, entry := range t.entries {
		for key, rule := range entry.redact {
			if key == "*" || matchesKey(key, fieldID, fieldName) {
				detectors |= rule
			}
		}
	}
	return detectors
}

// HasFieldRule reports whether the policy names this field specifically
// (hidden, or a field-level redaction rule).
func (t TablePolicy) HasFieldRule(fieldID, fieldName string) bool {
	if t.Hidden(fieldID, fieldName) {
		return true
	}
	for _, entry := range t.entries {
		for key := range entry.redact {
			if key != "*" && matchesKey(key, fieldID, fieldName) {
				return true
			}
		}
	}
	return false
}

func matchesKey(key, id, name string) bool {
	return key == id || strings.EqualFold(key, strings.TrimSpace(name))
}
