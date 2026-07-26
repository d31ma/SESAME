package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// EventGroupProvisioned records a group created by provisioning.
	EventGroupProvisioned = "scim.group_provisioned"
	// EventGroupUpdated records a provisioned change to a group's identity.
	EventGroupUpdated = "scim.group_updated"

	maxGroupMembers = 2000
)

// ErrTooManyMembers reports a membership change beyond what SESAME will apply
// in one request.
var ErrTooManyMembers = errors.New("the membership change exceeds the maximum")

// Group is the subset of an RFC 7643 Group that SESAME stores.
type Group struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id,omitempty"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []GroupMember `json:"members,omitempty"`
}

// GroupMember is one entry in a group's member list. Only `value` is read:
// it carries the principal identifier, and `display` and `type` are the
// directory's own labelling.
type GroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// ParseGroup validates a group provisioning payload.
func ParseGroup(document []byte) (Group, error) {
	var group Group
	if err := decodeResource(document, &group); err != nil {
		return Group{}, err
	}
	if err := requireSchema(group.Schemas, SchemaGroup); err != nil {
		return Group{}, err
	}
	if err := ValidateDisplayName(group.DisplayName); err != nil {
		return Group{}, err
	}
	if err := validateOptional("externalId", group.ExternalID, maxExternalIDLength); err != nil {
		return Group{}, err
	}
	return group, BoundMembers(len(group.Members))
}

// ValidateDisplayName enforces a bounded, printable group name.
//
// displayName maps onto a SESAME group name, which is a uniqueness claim
// inside a tenant — and groups carry roles, so two groups whose names differ
// only by padding is a privilege-confusion waiting to happen.
func ValidateDisplayName(displayName string) error {
	if displayName == "" || len(displayName) > maxDisplayLength {
		return fmt.Errorf("displayName is required and must not exceed %d bytes",
			maxDisplayLength)
	}
	if strings.TrimSpace(displayName) != displayName {
		return errors.New("displayName must not have leading or trailing whitespace")
	}
	return validateOptional("displayName", displayName, maxDisplayLength)
}

// BoundMembers refuses a membership list beyond what SESAME will apply in one
// request. Each member is a separate authorization-affecting event, so an
// unbounded list is an unbounded write.
func BoundMembers(count int) error {
	if count > maxGroupMembers {
		return fmt.Errorf("%w: %d exceeds %d", ErrTooManyMembers, count, maxGroupMembers)
	}
	return nil
}

// MembershipChange is one resolved instruction against a group's members.
type MembershipChange struct {
	// Add and Remove name principals. Replace is set when the operation
	// replaces the whole membership, in which case Add holds the new set.
	Add     []string
	Remove  []string
	Replace bool
}

// ParseGroupPatch resolves a PATCH body into membership and identity changes.
//
// Group PATCH is where SESAME has to read the one path shape it refuses
// everywhere else. Directories express member removal in two incompatible
// ways — `remove` with `path: "members"` and a value list, and `remove` with
// `path: members[value eq "..."]` — and a service provider that supports only
// one of them does not work with half the market.
//
// The value path is matched as one literal shape, not evaluated as an
// expression. `members[value eq "X"]` and nothing else: no other attribute,
// no other operator, no conjunction. That is a pattern match against a fixed
// string, which is a different thing from running a filter engine over
// attacker-influenced input to decide what identity state to mutate.
func ParseGroupPatch(document []byte) ([]MembershipChange, Group, error) {
	var request PatchRequest
	if err := decodeResource(document, &request); err != nil {
		return nil, Group{}, err
	}
	if err := requireSchema(request.Schemas, SchemaPatch); err != nil {
		return nil, Group{}, err
	}
	if err := boundOperations(len(request.Operations)); err != nil {
		return nil, Group{}, err
	}

	var changes []MembershipChange
	var identity Group
	for index, operation := range request.Operations {
		change, err := resolveGroupOperation(operation, &identity)
		if err != nil {
			return nil, Group{}, fmt.Errorf("operation %d: %w", index, err)
		}
		if change != nil {
			changes = append(changes, *change)
		}
	}
	return changes, identity, nil
}

// resolveGroupOperation reads one operation, folding a displayName change
// into identity and returning any membership change.
func resolveGroupOperation(
	operation PatchOperation,
	identity *Group,
) (*MembershipChange, error) {
	if removed, matched := matchMemberValuePath(operation.Path); matched {
		return removeByValuePath(operation.Op, removed)
	}
	switch strings.ToLower(strings.TrimSpace(operation.Path)) {
	case "members":
		return resolveMembersOperation(operation)
	case "displayname":
		return nil, foldDisplayName(operation.Value, identity)
	default:
		return nil, fmt.Errorf("%w: %q", ErrImmutableField, operation.Path)
	}
}

// matchMemberValuePath recognises exactly `members[value eq "X"]`.
func matchMemberValuePath(path string) (string, bool) {
	trimmed := strings.TrimSpace(path)
	const prefix = `members[value eq "`
	const suffix = `"]`
	if len(trimmed) <= len(prefix)+len(suffix) {
		return "", false
	}
	if !strings.EqualFold(trimmed[:len(prefix)], prefix) ||
		trimmed[len(trimmed)-len(suffix):] != suffix {
		return "", false
	}
	value := trimmed[len(prefix) : len(trimmed)-len(suffix)]
	// An embedded quote means the literal ended early and the rest is
	// something else — the shape an injection attempt takes here.
	if value == "" || strings.Contains(value, `"`) {
		return "", false
	}
	return value, true
}

func removeByValuePath(op, principalID string) (*MembershipChange, error) {
	if !strings.EqualFold(op, "remove") {
		return nil, fmt.Errorf(
			"%w: a member value path supports only remove, not %q", ErrUnsupportedSchema, op)
	}
	return &MembershipChange{Remove: []string{principalID}}, nil
}

// resolveMembersOperation reads add, remove, or replace on the whole list.
func resolveMembersOperation(operation PatchOperation) (*MembershipChange, error) {
	members, err := decodeMembers(operation.Value)
	if err != nil {
		return nil, err
	}
	values := memberValues(members)
	switch strings.ToLower(operation.Op) {
	case "add":
		return &MembershipChange{Add: values}, nil
	case "remove":
		return &MembershipChange{Remove: values}, nil
	case "replace":
		// A replace with no value empties the group, which is a legitimate
		// instruction and the most destructive one here.
		return &MembershipChange{Add: values, Replace: true}, nil
	default:
		return nil, fmt.Errorf("%w: %q on members", ErrUnsupportedSchema, operation.Op)
	}
}

func decodeMembers(raw json.RawMessage) ([]GroupMember, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var members []GroupMember
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("the members value must be a list of members: %w", err)
	}
	if err := BoundMembers(len(members)); err != nil {
		return nil, err
	}
	return members, nil
}

func memberValues(members []GroupMember) []string {
	values := make([]string, 0, len(members))
	for _, member := range members {
		if member.Value != "" {
			values = append(values, member.Value)
		}
	}
	return values
}

func foldDisplayName(raw json.RawMessage, identity *Group) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("the replacement displayName must be a string: %w", err)
	}
	if err := ValidateDisplayName(value); err != nil {
		return err
	}
	identity.DisplayName = value
	return nil
}
