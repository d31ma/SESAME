package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	// EventUserProvisioned records a principal created by provisioning.
	EventUserProvisioned = "scim.user_provisioned"
	// EventUserUpdated records a provisioned change to a principal.
	EventUserUpdated = "scim.user_updated"
	// EventUserDeprovisioned records a principal deactivated by provisioning.
	EventUserDeprovisioned = "scim.user_deprovisioned"

	// SchemaUser and SchemaGroup are the RFC 7643 resource schemas SESAME
	// implements. A payload declaring anything else is refused rather than
	// silently interpreted as one of these.
	SchemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	// SchemaPatch is the PATCH request schema from RFC 7644.
	SchemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	// SchemaListResponse and SchemaError are what SESAME returns.
	SchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"

	// MaxResourceBytes bounds one provisioning payload. Identity providers
	// send a few kilobytes; anything near this is an attempt to make parsing
	// expensive rather than a user record.
	MaxResourceBytes = 64 * 1024

	// MaxPageSize bounds a list response, whatever the caller asked for. An
	// unbounded count is how a directory read becomes a denial of service.
	MaxPageSize     = 200
	DefaultPageSize = 50

	maxUserNameLength   = 320
	maxExternalIDLength = 256
	maxDisplayLength    = 256
	maxPatchOperations  = 32
)

var (
	// ErrResourceTooLarge is returned when a payload exceeds the bound.
	ErrResourceTooLarge = errors.New("the provisioning payload exceeds the maximum size")
	// ErrUnsupportedSchema reports a resource SESAME does not model.
	ErrUnsupportedSchema = errors.New("unsupported SCIM schema")
	// ErrImmutableField reports an attempt to change something provisioning
	// may not change.
	ErrImmutableField = errors.New("this attribute cannot be changed through provisioning")
)

// User is the subset of an RFC 7643 User that SESAME stores.
//
// Everything outside this set is accepted and ignored rather than rejected:
// identity providers send large records with photos, addresses, and
// enterprise extensions, and refusing a sync because of a field SESAME has no
// use for would break provisioning for no security gain. What SESAME does not
// store, it also does not return.
type User struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	// Active drives deprovisioning. Absent means true, per RFC 7643.
	Active      *bool  `json:"active,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// ParseUser validates a provisioning payload.
func ParseUser(document []byte) (User, error) {
	var user User
	if err := decodeResource(document, &user); err != nil {
		return User{}, err
	}
	if err := requireSchema(user.Schemas, SchemaUser); err != nil {
		return User{}, err
	}
	if err := ValidateUserName(user.UserName); err != nil {
		return User{}, err
	}
	if err := validateOptional("externalId", user.ExternalID, maxExternalIDLength); err != nil {
		return User{}, err
	}
	if err := validateOptional("displayName", user.DisplayName, maxDisplayLength); err != nil {
		return User{}, err
	}
	return user, nil
}

// IsActive resolves the tri-state Active field. RFC 7643 makes an absent
// `active` mean true, and reading absence as "deactivate" would suspend every
// user an identity provider syncs without that attribute.
func (u User) IsActive() bool {
	return u.Active == nil || *u.Active
}

// ValidateUserName enforces a bounded, printable, whitespace-free userName.
//
// userName maps onto a SESAME identifier, which is a uniqueness claim inside
// a tenant. A value with leading or trailing space would create a second
// account that looks identical to a human reading a list.
func ValidateUserName(userName string) error {
	if userName == "" || len(userName) > maxUserNameLength {
		return fmt.Errorf("userName is required and must not exceed %d bytes", maxUserNameLength)
	}
	if strings.TrimSpace(userName) != userName {
		return errors.New("userName must not have leading or trailing whitespace")
	}
	for _, character := range userName {
		if unicode.IsControl(character) {
			return errors.New("userName must not contain control characters")
		}
	}
	return nil
}

func validateOptional(field, value string, limit int) error {
	if value == "" {
		return nil
	}
	if len(value) > limit {
		return fmt.Errorf("%s must not exceed %d bytes", field, limit)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

// decodeResource reads one bounded JSON document, strictly.
func decodeResource(document []byte, target any) error {
	if len(document) == 0 {
		return errors.New("the provisioning payload is empty")
	}
	if len(document) > MaxResourceBytes {
		return ErrResourceTooLarge
	}
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("the provisioning payload is not valid JSON: %w", err)
	}
	// A second value after the object means the body was not one resource,
	// which is a sign of a proxy or an injection rather than a provider.
	if decoder.More() {
		return errors.New("the provisioning payload contains trailing data")
	}
	return nil
}

// requireSchema enforces that the caller declared the schema it is sending.
func requireSchema(declared []string, want string) error {
	for _, schema := range declared {
		if schema == want {
			return nil
		}
	}
	return fmt.Errorf("%w: expected %s", ErrUnsupportedSchema, want)
}

// PatchOperation is one RFC 7644 PATCH instruction.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// PatchRequest is a bounded PATCH body.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// ParsePatch validates a PATCH body and the operations SESAME supports.
//
// The supported set is deliberately small: `replace` on `active`, `userName`,
// `displayName`, and `externalId`. RFC 7644's full path grammar includes
// filters inside paths — `members[value eq "x"]` — and implementing that
// means writing an expression evaluator that mutates identity state. The
// bounded set covers what identity providers actually send for users, and
// anything outside it is refused with a reason rather than half-applied.
func ParsePatch(document []byte) (PatchRequest, error) {
	var request PatchRequest
	if err := decodeResource(document, &request); err != nil {
		return PatchRequest{}, err
	}
	if err := requireSchema(request.Schemas, SchemaPatch); err != nil {
		return PatchRequest{}, err
	}
	if err := boundOperations(len(request.Operations)); err != nil {
		return PatchRequest{}, err
	}
	for index, operation := range request.Operations {
		if err := validatePatchOperation(operation); err != nil {
			return PatchRequest{}, fmt.Errorf("operation %d: %w", index, err)
		}
	}
	return request, nil
}

// patchablePaths are the attributes provisioning may replace. `id` is absent
// on purpose: it is SESAME's principal identifier, and letting a provisioning
// client reassign it would let one synced user become another.
var patchablePaths = map[string]struct{}{
	"active":      {},
	"userName":    {},
	"displayName": {},
	"externalId":  {},
}

func validatePatchOperation(operation PatchOperation) error {
	if !strings.EqualFold(operation.Op, "replace") {
		return fmt.Errorf("%w: only replace is supported, not %q",
			ErrUnsupportedSchema, operation.Op)
	}
	if strings.TrimSpace(operation.Path) == "" {
		return errors.New("a replace operation must name a path")
	}
	// A path carrying a filter or sub-attribute is well-formed SCIM that
	// SESAME will not act on, which is a different answer from "malformed".
	// The caller needs to tell those apart: one is fixed in the provider's
	// configuration, the other is a bug in the request.
	path := normalizePatchPath(operation.Path)
	if _, patchable := patchablePaths[path]; !patchable {
		return fmt.Errorf("%w: %q", ErrImmutableField, operation.Path)
	}
	if len(operation.Value) == 0 {
		return errors.New("a replace operation must carry a value")
	}
	return nil
}

// normalizePatchPath resolves the attribute a path names, case-insensitively
// as RFC 7643 requires.
//
// A path containing a filter or sub-attribute resolves to nothing patchable,
// so the caller reports it as unsupported rather than malformed.
func normalizePatchPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if strings.ContainsAny(trimmed, "[].") {
		return trimmed
	}
	for candidate := range patchablePaths {
		if strings.EqualFold(candidate, trimmed) {
			return candidate
		}
	}
	return trimmed
}

// boundOperations refuses an empty or unbounded operation list.
func boundOperations(count int) error {
	if count == 0 {
		return errors.New("a PATCH must carry at least one operation")
	}
	if count > maxPatchOperations {
		return fmt.Errorf("a PATCH must not carry more than %d operations", maxPatchOperations)
	}
	return nil
}

// UserProvisionedPayload is the versioned payload of EventUserProvisioned.
type UserProvisionedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"scim_client_id"`
	ExternalID  string `json:"external_id,omitempty"`
	UserName    string `json:"user_name"`
	DisplayName string `json:"display_name,omitempty"`
	Active      bool   `json:"active"`
	At          string `json:"at"`
}

// UserUpdatedPayload is the versioned payload of EventUserUpdated.
type UserUpdatedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"scim_client_id"`
	ExternalID  string `json:"external_id,omitempty"`
	UserName    string `json:"user_name"`
	DisplayName string `json:"display_name,omitempty"`
	At          string `json:"at"`
}

// UserDeprovisionedPayload is the versioned payload of
// EventUserDeprovisioned.
//
// Deprovisioning deactivates; it does not delete. A SCIM DELETE that erased a
// principal would erase the audit trail's subject along with it, and an
// operator investigating what that account did would find nothing.
type UserDeprovisionedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"scim_client_id"`
	At          string `json:"at"`
}
