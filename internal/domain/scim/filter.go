package scim

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedFilter reports a filter outside the supported subset.
var ErrUnsupportedFilter = errors.New("unsupported SCIM filter")

// Filter is a resolved equality filter.
//
// RFC 7644 defines a full expression language: `and`, `or`, `not`, grouping,
// nine operators, and value paths like `emails[type eq "work"]`. SESAME
// implements exactly one shape — `attribute eq "value"` — because that is
// what identity providers send when reconciling, and because the alternative
// is an expression evaluator running attacker-influenced input against
// identity state.
//
// Anything else is refused with a reason. A filter that is silently
// misinterpreted returns the wrong users, and in a provisioning reconcile
// that means deactivating people who should not have been touched.
type Filter struct {
	Attribute string
	Value     string
}

// filterableAttributes are the attributes a filter may name. Each is a
// uniqueness claim inside a tenant, which is what a reconciling directory
// actually looks up: userName and externalId identify a person, displayName
// identifies a group.
var filterableAttributes = map[string]string{
	"username":    "userName",
	"externalid":  "externalId",
	"displayname": "displayName",
}

// ParseFilter resolves a filter expression, or explains why it cannot.
//
// An empty filter is not an error: SCIM treats it as "all resources", and the
// caller bounds that with pagination.
func ParseFilter(expression string) (Filter, bool, error) {
	trimmed := strings.TrimSpace(expression)
	if trimmed == "" {
		return Filter{}, false, nil
	}
	if err := rejectCompoundFilter(trimmed); err != nil {
		return Filter{}, false, err
	}
	attribute, value, err := splitEquality(trimmed)
	if err != nil {
		return Filter{}, false, err
	}
	canonical, filterable := filterableAttributes[strings.ToLower(attribute)]
	if !filterable {
		return Filter{}, false, fmt.Errorf(
			"%w: %q is not filterable; SESAME supports userName, externalId, and displayName",
			ErrUnsupportedFilter, attribute)
	}
	return Filter{Attribute: canonical, Value: value}, true, nil
}

// rejectCompoundFilter refuses the operators SESAME does not evaluate, rather
// than parsing the first clause and ignoring the rest — which would answer a
// narrow question with a broad result set.
func rejectCompoundFilter(expression string) error {
	lowered := strings.ToLower(expression)
	for _, operator := range []string{" and ", " or ", "not ", "(", ")", "[", "]"} {
		if strings.Contains(lowered, operator) {
			return fmt.Errorf(
				"%w: compound expressions are not supported, only `attribute eq \"value\"`",
				ErrUnsupportedFilter)
		}
	}
	return nil
}

// splitEquality reads `attribute eq "value"`.
func splitEquality(expression string) (string, string, error) {
	fields := strings.SplitN(expression, " ", 3)
	if len(fields) != 3 {
		return "", "", fmt.Errorf(
			"%w: expected `attribute eq \"value\"`", ErrUnsupportedFilter)
	}
	if !strings.EqualFold(fields[1], "eq") {
		return "", "", fmt.Errorf(
			"%w: only the eq operator is supported, not %q", ErrUnsupportedFilter, fields[1])
	}
	value, err := unquote(strings.TrimSpace(fields[2]))
	if err != nil {
		return "", "", err
	}
	return fields[0], value, nil
}

// unquote reads a SCIM string literal.
func unquote(literal string) (string, error) {
	if len(literal) < 2 || literal[0] != '"' || literal[len(literal)-1] != '"' {
		return "", fmt.Errorf("%w: the compared value must be a quoted string",
			ErrUnsupportedFilter)
	}
	inner := literal[1 : len(literal)-1]
	// An unescaped quote inside means the literal ended early and the rest is
	// something else — the shape an injection attempt takes here.
	if strings.Contains(inner, `"`) {
		return "", fmt.Errorf("%w: the compared value contains an unescaped quote",
			ErrUnsupportedFilter)
	}
	return inner, nil
}

// Page is a resolved, bounded pagination window.
//
// SCIM indexes from 1, not 0. Treating a missing or zero startIndex as 0
// would silently shift every page by one and make a reconcile miss the first
// user forever.
type Page struct {
	StartIndex int
	Count      int
}

// ResolvePage bounds what a caller asked for.
func ResolvePage(startIndex, count int) Page {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = DefaultPageSize
	}
	if count > MaxPageSize {
		count = MaxPageSize
	}
	return Page{StartIndex: startIndex, Count: count}
}
