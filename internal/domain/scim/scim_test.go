package scim_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/domain/scim"
)

func userDocument(t *testing.T, overrides map[string]any) []byte {
	t.Helper()

	document := map[string]any{
		"schemas":  []string{scim.SchemaUser},
		"userName": "person@example.com",
	}
	for name, value := range overrides {
		if value == nil {
			delete(document, name)
			continue
		}
		document[name] = value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestParseUserAcceptsAProviderRecord(t *testing.T) {
	t.Parallel()

	// Identity providers send far more than SESAME stores. Unknown fields are
	// ignored rather than refused: rejecting a sync over a photo URL would
	// break provisioning for no security gain.
	user, err := scim.ParseUser(userDocument(t, map[string]any{
		"externalId":  "okta-00u1",
		"displayName": "A Person",
		"name":        map[string]any{"givenName": "A", "familyName": "Person"},
		"photos":      []any{map[string]any{"value": "https://example.com/p.jpg"}},
	}))
	if err != nil {
		t.Fatalf("ParseUser() error = %v", err)
	}
	if user.UserName != "person@example.com" || user.ExternalID != "okta-00u1" {
		t.Fatalf("parsed %#v", user)
	}
}

// TestAbsentActiveMeansActive is the deprovisioning trap. RFC 7643 makes an
// absent `active` mean true; reading absence as false would suspend every
// user a provider syncs without that attribute.
func TestAbsentActiveMeansActive(t *testing.T) {
	t.Parallel()

	user, err := scim.ParseUser(userDocument(t, nil))
	if err != nil {
		t.Fatalf("ParseUser() error = %v", err)
	}
	if !user.IsActive() {
		t.Fatal("a user with no active attribute was read as inactive")
	}

	deactivated, err := scim.ParseUser(userDocument(t, map[string]any{"active": false}))
	if err != nil {
		t.Fatalf("ParseUser() error = %v", err)
	}
	if deactivated.IsActive() {
		t.Fatal("active:false was read as active")
	}
}

func TestParseUserRefusesMalformedRecords(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"empty":         nil,
		"not JSON":      []byte("<html>an error page</html>"),
		"trailing data": append(userDocument(t, nil), userDocument(t, nil)...),
		"oversized":     make([]byte, scim.MaxResourceBytes+1),
		"wrong schema": userDocument(t, map[string]any{
			"schemas": []string{scim.SchemaGroup},
		}),
		"no schema":   userDocument(t, map[string]any{"schemas": nil}),
		"no userName": userDocument(t, map[string]any{"userName": nil}),
		// A padded userName would create a second account indistinguishable
		// from the first in any list a human reads.
		"padded userName":     userDocument(t, map[string]any{"userName": " person@example.com "}),
		"control character":   userDocument(t, map[string]any{"userName": "person\x00@example.com"}),
		"oversized userName":  userDocument(t, map[string]any{"userName": strings.Repeat("a", 400)}),
		"control in external": userDocument(t, map[string]any{"externalId": "okta\x07"}),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := scim.ParseUser(document); err == nil {
				t.Fatal("ParseUser accepted a record it must refuse")
			}
		})
	}
}

func patchDocument(t *testing.T, operations []map[string]any) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"schemas":    []string{scim.SchemaPatch},
		"Operations": operations,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestParsePatchAcceptsTheSupportedSubset(t *testing.T) {
	t.Parallel()

	request, err := scim.ParsePatch(patchDocument(t, []map[string]any{
		{"op": "replace", "path": "active", "value": false},
		// Paths are case-insensitive per RFC 7643.
		{"op": "Replace", "path": "userName", "value": "moved@example.com"},
	}))
	if err != nil {
		t.Fatalf("ParsePatch() error = %v", err)
	}
	if len(request.Operations) != 2 {
		t.Fatalf("parsed %d operations", len(request.Operations))
	}
}

// TestParsePatchRefusesWhatItCannotApply: a half-applied PATCH on identity
// state is worse than a refused one.
func TestParsePatchRefusesWhatItCannotApply(t *testing.T) {
	t.Parallel()

	cases := map[string][]map[string]any{
		"add":    {{"op": "add", "path": "active", "value": true}},
		"remove": {{"op": "remove", "path": "active"}},
		// Reassigning id would let one synced user become another.
		"id":            {{"op": "replace", "path": "id", "value": "prn_other"}},
		"unknown path":  {{"op": "replace", "path": "password", "value": "x"}},
		"no path":       {{"op": "replace", "value": true}},
		"no value":      {{"op": "replace", "path": "active"}},
		"sub-attribute": {{"op": "replace", "path": "name.givenName", "value": "A"}},
		// A value path is an expression, and SESAME evaluates none.
		"value filter": {{"op": "replace", "path": `emails[type eq "work"]`, "value": "x"}},
	}
	for name, operations := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := scim.ParsePatch(patchDocument(t, operations)); err == nil {
				t.Fatal("ParsePatch accepted an operation it cannot apply")
			}
		})
	}

	if _, err := scim.ParsePatch(patchDocument(t, nil)); err == nil {
		t.Fatal("ParsePatch accepted a body with no operations")
	}
	many := make([]map[string]any, 40)
	for index := range many {
		many[index] = map[string]any{"op": "replace", "path": "active", "value": true}
	}
	if _, err := scim.ParsePatch(patchDocument(t, many)); err == nil {
		t.Fatal("ParsePatch accepted an unbounded operation list")
	}
}

func TestParseFilterAcceptsEquality(t *testing.T) {
	t.Parallel()

	filter, present, err := scim.ParseFilter(`userName eq "person@example.com"`)
	if err != nil || !present {
		t.Fatalf("ParseFilter() = %v, %v, %v", filter, present, err)
	}
	if filter.Attribute != "userName" || filter.Value != "person@example.com" {
		t.Fatalf("parsed %#v", filter)
	}
	// Attribute names are case-insensitive and normalise to the canonical form.
	filter, _, err = scim.ParseFilter(`EXTERNALID EQ "okta-00u1"`)
	if err != nil {
		t.Fatalf("ParseFilter() error = %v", err)
	}
	if filter.Attribute != "externalId" {
		t.Fatalf("attribute = %q", filter.Attribute)
	}
	// An absent filter means "all", bounded by pagination, not an error.
	if _, present, err := scim.ParseFilter("   "); present || err != nil {
		t.Fatalf("an empty filter returned present=%v err=%v", present, err)
	}
}

// TestParseFilterRefusesWhatItCannotEvaluate is the one that matters: a
// filter parsed loosely returns the wrong users, and during a reconcile that
// means deactivating people who should not have been touched.
func TestParseFilterRefusesWhatItCannotEvaluate(t *testing.T) {
	t.Parallel()

	cases := []string{
		`userName eq "a" and active eq true`,
		`userName eq "a" or userName eq "b"`,
		`not (userName eq "a")`,
		`emails[type eq "work"].value eq "a"`,
		`userName co "example"`,
		`userName sw "a"`,
		`userName pr`,
		`active eq true`,
		`userName eq unquoted`,
		`userName eq "a" extra`,
		`userName eq "a" and`,
	}
	for _, expression := range cases {
		t.Run(expression, func(t *testing.T) {
			t.Parallel()

			if _, _, err := scim.ParseFilter(expression); err == nil {
				t.Fatalf("ParseFilter accepted %q", expression)
			} else if !errors.Is(err, scim.ErrUnsupportedFilter) {
				t.Fatalf("error = %v, want ErrUnsupportedFilter", err)
			}
		})
	}
}

// TestResolvePageIsOneIndexed: SCIM counts from 1. Treating a missing
// startIndex as 0 would shift every page and make a reconcile permanently
// miss the first user.
func TestResolvePageIsOneIndexed(t *testing.T) {
	t.Parallel()

	if page := scim.ResolvePage(0, 0); page.StartIndex != 1 {
		t.Fatalf("startIndex = %d, want 1", page.StartIndex)
	}
	if page := scim.ResolvePage(-5, 10); page.StartIndex != 1 {
		t.Fatalf("startIndex = %d, want 1", page.StartIndex)
	}
	if page := scim.ResolvePage(1, 0); page.Count != scim.DefaultPageSize {
		t.Fatalf("count = %d, want the default", page.Count)
	}
	// Whatever the caller asks for, the ceiling holds.
	if page := scim.ResolvePage(1, 100_000); page.Count != scim.MaxPageSize {
		t.Fatalf("count = %d, want the maximum %d", page.Count, scim.MaxPageSize)
	}
}

func TestTokensAreVerifiedInConstantTimeAndNeverRecoverable(t *testing.T) {
	t.Parallel()

	token, digest, err := scim.NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if !scim.VerifyToken(token, digest) {
		t.Fatal("VerifyToken rejected the token it hashed")
	}
	if scim.VerifyToken("a-forged-token", digest) {
		t.Fatal("VerifyToken accepted a forged token")
	}
	// Fail closed on empty input rather than treating two blanks as a match.
	if scim.VerifyToken("", digest) || scim.VerifyToken(token, "") {
		t.Fatal("VerifyToken accepted an empty credential")
	}
	if strings.Contains(digest, token) {
		t.Fatal("the stored digest contains the token")
	}
	if len(token) < 43 {
		t.Fatalf("token is %d characters, too short for 32 random bytes", len(token))
	}
}

func TestParseBearer(t *testing.T) {
	t.Parallel()

	token, err := scim.ParseBearer("Bearer abc123")
	if err != nil || token != "abc123" {
		t.Fatalf("ParseBearer() = %q, %v", token, err)
	}
	// RFC 7235 makes the scheme case-insensitive; a provider sending "bearer"
	// would otherwise fail in a way nobody can diagnose from outside.
	if token, err := scim.ParseBearer("bearer abc123"); err != nil || token != "abc123" {
		t.Fatalf("ParseBearer() lowercase = %q, %v", token, err)
	}
	for _, header := range []string{"", "Bearer", "Bearer ", "Basic abc123", "abc123"} {
		if _, err := scim.ParseBearer(header); err == nil {
			t.Fatalf("ParseBearer accepted %q", header)
		}
	}
}

func TestClientIdentifiersRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := scim.NewClientID()
	if err != nil {
		t.Fatalf("NewClientID() error = %v", err)
	}
	if err := scim.ValidateClientID(id); err != nil {
		t.Fatalf("ValidateClientID(%q) error = %v", id, err)
	}
	for _, bad := range []string{"", "scm_", "cli_" + strings.Repeat("a", 32), "scm_zzzz"} {
		if err := scim.ValidateClientID(bad); err == nil {
			t.Fatalf("ValidateClientID(%q) accepted a malformed identifier", bad)
		}
	}
}

func TestValidateName(t *testing.T) {
	t.Parallel()

	if err := scim.ValidateName("Okta production"); err != nil {
		t.Fatalf("ValidateName() error = %v", err)
	}
	for name, value := range map[string]string{
		"empty":             "",
		"control character": "Okta\x07",
		"oversized":         strings.Repeat("a", 200),
	} {
		t.Run(name, func(t *testing.T) {
			if err := scim.ValidateName(value); err == nil {
				t.Fatalf("ValidateName accepted %q", value)
			}
		})
	}
}

// TestNormalizeIdentifierNamespace covers the per-client namespace. Getting
// this wrong splits one person into two principals: provisioned under one
// namespace, federated under another.
func TestNormalizeIdentifierNamespace(t *testing.T) {
	t.Parallel()

	resolved, err := scim.NormalizeIdentifierNamespace("")
	if err != nil || resolved != scim.DefaultIdentifierNamespace {
		t.Fatalf("NormalizeIdentifierNamespace(\"\") = %q, %v", resolved, err)
	}
	if resolved, err := scim.NormalizeIdentifierNamespace("login_name"); err != nil ||
		resolved != "login_name" {
		t.Fatalf("NormalizeIdentifierNamespace() = %q, %v", resolved, err)
	}
	for name, value := range map[string]string{
		"uppercase":         "Email",
		"space":             "login name",
		"punctuation":       "login-name",
		"control character": "email\x07",
		"oversized":         strings.Repeat("a", 100),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scim.NormalizeIdentifierNamespace(value); err == nil {
				t.Fatalf("NormalizeIdentifierNamespace accepted %q", value)
			}
		})
	}
}
