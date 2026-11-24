package fieldpolicy

import (
	"fmt"
	"regexp"
	"strings"
)

// Detectors is a set of PII detectors.
type Detectors uint8

const (
	DetectEmail Detectors = 1 << iota
	DetectPhone
	DetectSSN
	DetectCreditCard
	DetectIPAddress
	// DetectFull replaces the whole value, for free text whose PII (names,
	// addresses) no pattern can find.
	DetectFull

	detectAllPatterns = DetectEmail | DetectPhone | DetectSSN | DetectCreditCard | DetectIPAddress
)

var detectorNames = map[string]Detectors{
	"email":       DetectEmail,
	"phone":       DetectPhone,
	"ssn":         DetectSSN,
	"credit_card": DetectCreditCard,
	"ip_address":  DetectIPAddress,
	"all":         detectAllPatterns,
	"full":        DetectFull,
}

func parseDetectors(names []string, where string) (Detectors, error) {
	var detectors Detectors
	for _, name := range names {
		detector, ok := detectorNames[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return 0, fmt.Errorf("field policy: %s: unknown detector %q (use email, phone, ssn, credit_card, ip_address, all, or full)", where, name)
		}
		detectors |= detector
	}
	return detectors, nil
}

// Placeholders that replace redacted values. They are what the agent sees.
const (
	PlaceholderFull = "[REDACTED]"
)

// Patterns run in this order: emails first (they may contain digit runs),
// then card numbers before the shorter phone pattern can claim part of one.
var patterns = []struct {
	detector    Detectors
	re          *regexp.Regexp
	placeholder string
	accept      func(string) bool
}{
	{DetectEmail, regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`), "[REDACTED_EMAIL]", nil},
	{DetectCreditCard, regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`), "[REDACTED_CREDIT_CARD]", luhnValid},
	{DetectSSN, regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "[REDACTED_SSN]", nil},
	{DetectIPAddress, regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`), "[REDACTED_IP_ADDRESS]", nil},
	{DetectPhone, regexp.MustCompile(`\+\d[\d\s().-]{6,}\d|(?:\(\d{3}\)\s?|\b\d{3}[\s.-]?)\d{3}[\s.-]?\d{4}\b`), "[REDACTED_PHONE]", nil},
}

var placeholderPattern = regexp.MustCompile(`\[REDACTED(?:_[A-Z_]+)?\]`)

// RedactString replaces every detected PII match in value.
func (d Detectors) RedactString(value string) string {
	if d&DetectFull != 0 {
		if value == "" {
			return value
		}
		return PlaceholderFull
	}
	for _, pattern := range patterns {
		if d&pattern.detector == 0 {
			continue
		}
		value = pattern.re.ReplaceAllStringFunc(value, func(match string) string {
			if pattern.accept != nil && !pattern.accept(match) {
				return match
			}
			return pattern.placeholder
		})
	}
	return value
}

// Redact applies the detectors to an Airtable cell value, walking arrays and
// objects (lookups, attachments, collaborators) and leaving numbers, booleans,
// and object keys alone. With DetectFull, a value bound for a text-typed
// column becomes "[REDACTED]"; any other value becomes nil, since a typed
// column (number, date, checkbox) cannot hold the placeholder.
func (d Detectors) Redact(value any, textColumn bool) any {
	if d == 0 || value == nil {
		return value
	}
	if d&DetectFull != 0 {
		if textColumn {
			return PlaceholderFull
		}
		return nil
	}
	switch typed := value.(type) {
	case string:
		return d.RedactString(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = d.Redact(item, textColumn)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = d.Redact(item, textColumn)
		}
		return result
	default:
		return value
	}
}

// ContainsPlaceholder reports whether a value (or anything nested in it)
// contains a redaction placeholder. Writing one back to Airtable would
// overwrite real data with the redacted copy the agent was shown.
func ContainsPlaceholder(value any) bool {
	switch typed := value.(type) {
	case string:
		return placeholderPattern.MatchString(typed)
	case []any:
		for _, item := range typed {
			if ContainsPlaceholder(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if ContainsPlaceholder(item) {
				return true
			}
		}
	}
	return false
}

func luhnValid(match string) bool {
	sum := 0
	double := false
	digits := 0
	for index := len(match) - 1; index >= 0; index-- {
		char := match[index]
		if char < '0' || char > '9' {
			continue
		}
		digit := int(char - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
		digits++
	}
	return digits >= 13 && sum%10 == 0
}
