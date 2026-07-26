// Package authorization defines tenant-scoped roles, grants, and the
// deterministic pattern language used by authorization decisions.
package authorization

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const (
	// EventRoleCreated records an immutable role definition.
	EventRoleCreated = "role.created"
	// EventGrantCreated records a role assignment to a principal.
	EventGrantCreated = "grant.created"
	// EventGrantRevoked records a durable, replay-safe grant revocation.
	EventGrantRevoked = "grant.revoked"

	// EventGroupCreated records a named group inside one tenant.
	EventGroupCreated = "group.created"
	// EventGroupMemberAdded records a principal joining a group.
	EventGroupMemberAdded = "group.member_added"
	// EventGroupMemberRemoved records a durable membership removal.
	EventGroupMemberRemoved = "group.member_removed"

	// RoleIDPrefix, GrantIDPrefix, and GroupIDPrefix distinguish public
	// identifiers.
	RoleIDPrefix  = "rol_"
	GrantIDPrefix = "grt_"
	GroupIDPrefix = "grp_"

	maxPatternLength      = 128
	maxPermissionCount    = 64
	maxContextKeyLength   = 64
	maxContextValueLength = 256
	maxContextAttributes  = 32
	maxConditionCount     = 8
)

// Permission pairs one action pattern with one resource pattern, optionally
// requiring context attributes to equal exact values.
//
// Conditions are deliberately equality-only. A general condition language
// (CEL or similar) needs the ADR and abuse review the project plan requires;
// exact equality is decidable, side-effect free, and cannot be made to loop.
type Permission struct {
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// ConditionsSatisfied reports whether context supplies every required
// attribute with the exact required value, and names the first absent
// attribute in sorted order.
//
// An attribute is only reported missing when supplying it would actually
// change the outcome: if any supplied attribute holds the wrong value, the
// request is denied without naming anything, because "provide this
// attribute" would be false advice. All conditions are examined rather than
// short-circuiting so the answer does not depend on map ordering.
func (p Permission) ConditionsSatisfied(context map[string]string) (satisfied bool, missing string) {
	mismatched := false
	for _, key := range sortedKeys(p.Conditions) {
		value, present := context[key]
		switch {
		case !present:
			if missing == "" {
				missing = key
			}
		case value != p.Conditions[key]:
			mismatched = true
		}
	}
	if mismatched {
		return false, ""
	}
	return missing == "", missing
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ValidateContextKey enforces the bounded attribute-name shape.
func ValidateContextKey(key string) error {
	if key == "" || len(key) > maxContextKeyLength {
		return fmt.Errorf("context key is required and must not exceed %d bytes", maxContextKeyLength)
	}
	for _, character := range key {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		// '.' allows the reserved "session." prefix the engine derives.
		case character == '_' || character == '.':
		default:
			return fmt.Errorf("context key contains unsupported character %q", character)
		}
	}
	return nil
}

// ValidateContextValue enforces the bounded attribute-value shape.
func ValidateContextValue(value string) error {
	if value == "" || len(value) > maxContextValueLength {
		return fmt.Errorf("context value is required and must not exceed %d bytes", maxContextValueLength)
	}
	if strings.ContainsAny(value, "=;,") {
		return errors.New("context value must not contain '=', ';', or ','")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("context value must not contain control characters")
		}
	}
	return nil
}

// ValidateContext enforces the bounded shape of a decision request context.
func ValidateContext(context map[string]string) error {
	if len(context) > maxContextAttributes {
		return fmt.Errorf("context must not exceed %d attributes", maxContextAttributes)
	}
	for key, value := range context {
		if err := ValidateContextKey(key); err != nil {
			return err
		}
		if err := ValidateContextValue(value); err != nil {
			return err
		}
	}
	return nil
}

// Role is an immutable named set of permissions inside one tenant.
type Role struct {
	ID          string       `json:"role_id"`
	TenantID    string       `json:"tenant_id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

// Grant assigns one role to exactly one subject — a principal or a group —
// inside one tenant.
type Grant struct {
	ID          string `json:"grant_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	RoleID      string `json:"role_id"`
}

// Group is a named set of principals inside one tenant.
type Group struct {
	ID       string `json:"group_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// GroupCreatedPayload is the versioned payload of an EventGroupCreated event.
type GroupCreatedPayload struct {
	GroupID  string `json:"group_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// GroupMemberPayload is the versioned payload of membership events.
type GroupMemberPayload struct {
	GroupID     string `json:"group_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
}

// RoleCreatedPayload is the versioned payload of an EventRoleCreated event.
// Permissions are stored as "action=resource" pairs: FYLO's document model
// deliberately rejects embedded arrays of objects (they belong in their own
// collection), and an event must stay one atomic document, so the pairs are
// flattened to scalars instead of split across collections.
type RoleCreatedPayload struct {
	RoleID      string   `json:"role_id"`
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// EncodePermissions flattens permissions to stored strings of the form
// "action=resource" with conditions appended as ";key=value" in sorted key
// order, so one role always encodes identically.
func EncodePermissions(permissions []Permission) []string {
	pairs := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		encoded := permission.Action + "=" + permission.Resource
		for _, key := range sortedKeys(permission.Conditions) {
			encoded += ";" + key + "=" + permission.Conditions[key]
		}
		pairs = append(pairs, encoded)
	}
	return pairs
}

// DecodePermissions restores and validates stored permission strings.
func DecodePermissions(pairs []string) ([]Permission, error) {
	permissions := make([]Permission, 0, len(pairs))
	for _, pair := range pairs {
		segments := strings.Split(pair, ";")
		action, resource, found := strings.Cut(segments[0], "=")
		if !found {
			return nil, fmt.Errorf("stored permission %q is not action=resource", pair)
		}
		permission := Permission{Action: action, Resource: resource}
		for _, condition := range segments[1:] {
			key, value, found := strings.Cut(condition, "=")
			if !found {
				return nil, fmt.Errorf("stored condition %q is not key=value", condition)
			}
			if permission.Conditions == nil {
				permission.Conditions = make(map[string]string)
			}
			if _, duplicate := permission.Conditions[key]; duplicate {
				return nil, fmt.Errorf("stored permission %q repeats condition %q", pair, key)
			}
			permission.Conditions[key] = value
		}
		permissions = append(permissions, permission)
	}
	if err := ValidatePermissions(permissions); err != nil {
		return nil, err
	}
	return permissions, nil
}

// GrantCreatedPayload is the versioned payload of an EventGrantCreated event.
type GrantCreatedPayload struct {
	GrantID     string `json:"grant_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	RoleID      string `json:"role_id"`
}

// GrantRevokedPayload is the versioned payload of an EventGrantRevoked event.
type GrantRevokedPayload struct {
	GrantID  string `json:"grant_id"`
	TenantID string `json:"tenant_id"`
}

// ValidatePattern enforces the deterministic pattern shape shared by
// permissions: lower-case segments joined by ":", where only the final
// segment may be the wildcard "*".
func ValidatePattern(pattern string) error {
	if pattern == "" {
		return errors.New("pattern is required")
	}
	if len(pattern) > maxPatternLength {
		return fmt.Errorf("pattern must not exceed %d bytes", maxPatternLength)
	}
	segments := strings.Split(pattern, ":")
	for index, segment := range segments {
		if segment == "*" {
			if index != len(segments)-1 {
				return errors.New("wildcard is only permitted as the final pattern segment")
			}
			continue
		}
		if segment == "" {
			return errors.New("pattern contains an empty segment")
		}
		for _, character := range segment {
			switch {
			case character >= 'a' && character <= 'z':
			case character >= '0' && character <= '9':
			case character == '-' || character == '_' || character == '.':
			default:
				return fmt.Errorf("pattern contains unsupported character %q", character)
			}
		}
	}
	return nil
}

// ValidateValue enforces the shape of a concrete action or resource in a
// decision request: a pattern with no wildcard.
func ValidateValue(value string) error {
	if err := ValidatePattern(value); err != nil {
		return err
	}
	if strings.HasSuffix(value, "*") {
		return errors.New("decision requests must name a concrete action and resource, not a pattern")
	}
	return nil
}

// Matches reports whether one concrete value satisfies one pattern. Matching
// is deterministic: exact segment equality, with a final "*" matching any
// remaining segments (including none is not permitted; "doc:*" does not
// match "doc").
func Matches(pattern, value string) bool {
	patternSegments := strings.Split(pattern, ":")
	valueSegments := strings.Split(value, ":")
	for index, segment := range patternSegments {
		if segment == "*" {
			return len(valueSegments) > index
		}
		if index >= len(valueSegments) || valueSegments[index] != segment {
			return false
		}
	}
	return len(valueSegments) == len(patternSegments)
}

// ValidatePermissions enforces a bounded, well-formed permission set.
func ValidatePermissions(permissions []Permission) error {
	if len(permissions) == 0 {
		return errors.New("a role requires at least one permission")
	}
	if len(permissions) > maxPermissionCount {
		return fmt.Errorf("a role must not exceed %d permissions", maxPermissionCount)
	}
	for _, permission := range permissions {
		if err := ValidatePattern(permission.Action); err != nil {
			return fmt.Errorf("action %q: %w", permission.Action, err)
		}
		if err := ValidatePattern(permission.Resource); err != nil {
			return fmt.Errorf("resource %q: %w", permission.Resource, err)
		}
		if len(permission.Conditions) > maxConditionCount {
			return fmt.Errorf("a permission must not exceed %d conditions", maxConditionCount)
		}
		for key, value := range permission.Conditions {
			if err := ValidateContextKey(key); err != nil {
				return fmt.Errorf("condition key: %w", err)
			}
			if err := ValidateContextValue(value); err != nil {
				return fmt.Errorf("condition value: %w", err)
			}
		}
	}
	return nil
}

// NewRoleID returns a random public role identifier.
func NewRoleID() (string, error) { return newID(RoleIDPrefix) }

// NewGrantID returns a random public grant identifier.
func NewGrantID() (string, error) { return newID(GrantIDPrefix) }

// NewGroupID returns a random public group identifier.
func NewGroupID() (string, error) { return newID(GroupIDPrefix) }

// ValidateGroupID rejects values that cannot be group identifiers.
func ValidateGroupID(id string) error { return validateID(id, GroupIDPrefix, "group") }

// ValidateRoleID rejects values that cannot be role identifiers.
func ValidateRoleID(id string) error { return validateID(id, RoleIDPrefix, "role") }

// ValidateGrantID rejects values that cannot be grant identifiers.
func ValidateGrantID(id string) error { return validateID(id, GrantIDPrefix, "grant") }

func newID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate %sidentifier: %w", prefix, err)
	}
	return prefix + hex.EncodeToString(value), nil
}

func validateID(id, prefix, kind string) error {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+32 {
		return fmt.Errorf("%s ID must be %s followed by 32 hex characters", kind, prefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, prefix)); err != nil {
		return fmt.Errorf("%s ID must be %s followed by 32 hex characters", kind, prefix)
	}
	return nil
}
