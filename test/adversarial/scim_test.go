package adversarial_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/clients/go/sesame"
)

// Provisioning attacks, driven through the shipped binary over the shipped
// machine protocol against a real deployment.
//
// Provisioning is the most privileged non-administrative surface SESAME has:
// a directory that can create principals and rewrite identifiers can redirect
// or manufacture an account. These cases prove the refusals where an attacker
// stands rather than at a package boundary.

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// provision registers a provisioning client on a real deployment and returns
// its identifier and bearer token.
func provision(t *testing.T, deploy *deployment) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	registered, err := deploy.client.ProvisioningClientRegister(ctx, deploy.tenantID,
		"Hostile directory", "", false)
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	client, ok := registered["client"].(map[string]any)
	if !ok {
		t.Fatalf("registration returned no client: %#v", registered)
	}
	clientID, _ := client["scim_client_id"].(string)
	token, _ := registered["token"].(string)
	if clientID == "" || token == "" {
		t.Fatalf("registration returned %#v", registered)
	}
	return clientID, token
}

func scimUser(t *testing.T, overrides map[string]any) string {
	t.Helper()

	document := map[string]any{
		"schemas":  []string{scimUserSchema},
		"userName": "intruder@example.com",
	}
	for name, value := range overrides {
		document[name] = value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// TestProvisioningRequiresACredential proves every resource operation
// authenticates, so none can be reached by a caller who simply omits the
// token.
func TestProvisioningRequiresACredential(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for name, presented := range map[string]string{
		"empty":     "",
		"forged":    "a-forged-token",
		"truncated": token[:len(token)-1],
		"extended":  token + "x",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := deploy.client.SCIMUserCreate(ctx, presented, scimUser(t, nil))
			refused(t, "provisioning with a "+name+" token", err, "provisioning_denied")
		})
	}
}

// TestProvisioningCannotCaptureAnExistingAccount is the takeover this surface
// most obviously enables: claim the userName of somebody who already exists.
func TestProvisioningCannotCaptureAnExistingAccount(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// The deployment's principal is victim@example.com.
	_, err := deploy.client.SCIMUserCreate(ctx, token,
		scimUser(t, map[string]any{"userName": "victim@example.com"}))
	refused(t, "provisioning over an existing account", err, "scim_user_conflict")
}

// TestProvisioningCannotReassignAnIdentity: `id` is the principal identifier,
// and a PATCH that reassigned it would let one synced user become another.
func TestProvisioningCannotReassignAnIdentity(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	created, err := deploy.client.SCIMUserCreate(ctx, token, scimUser(t, nil))
	if err != nil {
		t.Fatalf("SCIMUserCreate() error = %v", err)
	}
	resourceID, _ := created["id"].(string)
	if resourceID == "" {
		t.Fatalf("create returned %#v", created)
	}

	for name, body := range map[string]string{
		"reassign id":      scimPatch(t, "replace", "id", "prn_0000"),
		"set a password":   scimPatch(t, "replace", "password", "hunter2"),
		"add an attribute": scimPatch(t, "add", "active", false),
		"remove active":    scimPatch(t, "remove", "active", nil),
		"value path":       scimPatch(t, "replace", `emails[type eq "work"]`, "x"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := deploy.client.SCIMUserPatch(ctx, token, resourceID, body)
			refused(t, "provisioning PATCH: "+name, err, "scim_unsupported")
		})
	}
}

func scimPatch(t *testing.T, op, path string, value any) string {
	t.Helper()

	operation := map[string]any{"op": op, "path": path}
	if value != nil {
		operation["value"] = value
	}
	raw, err := json.Marshal(map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{operation},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// TestProvisioningCannotReactivateASuspendedPrincipal: a directory that could
// would undo an administrator's decision with a sync.
func TestProvisioningCannotReactivateASuspendedPrincipal(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	created, err := deploy.client.SCIMUserCreate(ctx, token, scimUser(t, nil))
	if err != nil {
		t.Fatalf("SCIMUserCreate() error = %v", err)
	}
	resourceID, _ := created["id"].(string)

	// An administrator suspends the principal directly.
	if _, err := deploy.client.PrincipalSuspend(ctx, resourceID); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	patched, err := deploy.client.SCIMUserPatch(ctx, token, resourceID,
		scimPatch(t, "replace", "active", true))
	if err != nil {
		t.Fatalf("SCIMUserPatch() error = %v", err)
	}
	if active, _ := patched["active"].(bool); active {
		t.Fatal("a directory reactivated a principal an administrator suspended")
	}
}

// TestProvisioningFiltersAreNotEvaluated: a loosely parsed filter returns the
// wrong users, and during a reconcile that deactivates people who should not
// have been touched.
func TestProvisioningFiltersAreNotEvaluated(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, expression := range []string{
		`userName eq "a" or userName eq "b"`,
		`not (userName eq "a")`,
		`emails[type eq "work"].value eq "a"`,
		`userName co "example"`,
		`active eq true`,
	} {
		t.Run(expression, func(t *testing.T) {
			_, err := deploy.client.SCIMUserList(ctx, token, expression, 1, 50)
			refused(t, "provisioning filter "+expression, err, "scim_unsupported")
		})
	}
}

// TestProvisioningCrossTenantSubstitution proves one tenant's directory
// cannot see or touch another tenant's users.
func TestProvisioningCrossTenantSubstitution(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	created, err := deploy.client.SCIMUserCreate(ctx, token, scimUser(t, nil))
	if err != nil {
		t.Fatalf("SCIMUserCreate() error = %v", err)
	}
	resourceID, _ := created["id"].(string)

	attacker, err := deploy.client.TenantBootstrap(ctx, "scim-attacker")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	registered, err := deploy.client.ProvisioningClientRegister(ctx, attacker.Tenant.ID,
		"Attacker directory", "", false)
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	intruderToken, _ := registered["token"].(string)

	t.Run("read", func(t *testing.T) {
		_, err := deploy.client.SCIMUserGet(ctx, intruderToken, resourceID)
		refused(t, "cross-tenant provisioning read", err, "scim_user_not_found")
	})

	t.Run("deprovision", func(t *testing.T) {
		_, err := deploy.client.SCIMUserDeprovision(ctx, intruderToken, resourceID)
		refused(t, "cross-tenant deprovision", err, "scim_user_not_found")
	})

	t.Run("list", func(t *testing.T) {
		listed, err := deploy.client.SCIMUserList(ctx, intruderToken, "", 1, 50)
		if err != nil {
			t.Fatalf("SCIMUserList() error = %v", err)
		}
		if total, _ := listed["totalResults"].(float64); total != 0 {
			t.Fatalf("another tenant's directory saw %v users", total)
		}
	})
}

// TestProvisioningRotationClosesTheWindow: a leaked token must stop working
// the moment its replacement exists.
func TestProvisioningRotationClosesTheWindow(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	clientID, leaked := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if _, err := deploy.client.ProvisioningClientRotateToken(ctx,
		deploy.tenantID, clientID); err != nil {
		t.Fatalf("ProvisioningClientRotateToken() error = %v", err)
	}
	_, err := deploy.client.SCIMUserCreate(ctx, leaked, scimUser(t, nil))
	refused(t, "provisioning with a rotated-out token", err, "provisioning_denied")
}

// TestProvisioningDisableStopsEverything covers the remedy for a directory
// that is no longer trusted at all.
func TestProvisioningDisableStopsEverything(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	clientID, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if _, err := deploy.client.ProvisioningClientDisable(ctx, deploy.tenantID,
		clientID, "compromised"); err != nil {
		t.Fatalf("ProvisioningClientDisable() error = %v", err)
	}
	_, err := deploy.client.SCIMUserCreate(ctx, token, scimUser(t, nil))
	refused(t, "provisioning through a disabled client", err, "provisioning_denied")
}

// TestProvisioningPayloadsAreBounded proves the engine refuses what it will
// not parse, rather than reading it.
func TestProvisioningPayloadsAreBounded(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for name, body := range map[string]string{
		"oversized":     `{"schemas":["` + scimUserSchema + `"],"userName":"` + strings.Repeat("a", 400) + `"}`,
		"wrong schema":  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"userName":"x@example.com"}`,
		"no schema":     `{"userName":"x@example.com"}`,
		"trailing data": scimUser(t, nil) + scimUser(t, nil),
		// A padded userName would create an account indistinguishable from
		// the real one in any list a human reads.
		"padded userName": `{"schemas":["` + scimUserSchema + `"],"userName":" victim@example.com "}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := deploy.client.SCIMUserCreate(ctx, token, body); err == nil {
				t.Fatalf("the engine accepted a %s payload", name)
			}
		})
	}
}

// TestProvisioningGroupsRequireTheGrant is the escalation this surface would
// otherwise allow. Group membership drives authorization decisions here, so a
// directory that can change it can grant privilege — and a directory
// configured only to create and deactivate people must not be able to.
func TestProvisioningGroupsRequireTheGrant(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	_, token := provision(t, deploy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	body := scimGroup(t, "engineering")
	for name, call := range map[string]func() error{
		"create": func() error {
			_, err := deploy.client.SCIMGroupCreate(ctx, token, body)
			return err
		},
		"get": func() error {
			_, err := deploy.client.SCIMGroupGet(ctx, token, "grp_x")
			return err
		},
		"list": func() error {
			_, err := deploy.client.SCIMGroupList(ctx, token, "", 1, 50)
			return err
		},
		"patch": func() error {
			_, err := deploy.client.SCIMGroupPatch(ctx, token, "grp_x",
				scimGroupPatch(t, "add", "members", "prn_0000"))
			return err
		},
		"deprovision": func() error {
			_, err := deploy.client.SCIMGroupDeprovision(ctx, token, "grp_x")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			refused(t, "group "+name+" without the grant", call(), "provisioning_forbidden")
		})
	}
}

func scimGroup(t *testing.T, displayName string, members ...string) string {
	t.Helper()

	entries := make([]map[string]any, 0, len(members))
	for _, member := range members {
		entries = append(entries, map[string]any{"value": member})
	}
	raw, err := json.Marshal(map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": displayName,
		"members":     entries,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// TestProvisioningGroupsCannotRecruitAcrossTenants: a directory naming an
// arbitrary principal identifier would otherwise put somebody else's user
// into a group that carries a role here.
func TestProvisioningGroupsCannotRecruitAcrossTenants(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// A directory that may manage groups in this tenant.
	registered, err := deploy.client.ProvisioningClientRegister(ctx, deploy.tenantID,
		"Group directory", "", true)
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	token, _ := registered["token"].(string)

	// And somebody else's principal, in another tenant entirely.
	outsiderTenant, err := deploy.client.TenantBootstrap(ctx, "group-outsider")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	outsider, err := deploy.client.PrincipalCreate(ctx, outsiderTenant.Tenant.ID, "human",
		sesame.PrincipalIdentifier{Namespace: "email", Value: "outsider@example.com"})
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	created, err := deploy.client.SCIMGroupCreate(ctx, token, scimGroup(t, "engineering"))
	if err != nil {
		t.Fatalf("SCIMGroupCreate() error = %v", err)
	}
	groupID, _ := created["id"].(string)
	if groupID == "" {
		t.Fatalf("create returned %#v", created)
	}

	patch := scimGroupPatch(t, "add", "members", outsider.ID)
	if _, err := deploy.client.SCIMGroupPatch(ctx, token, groupID, patch); err == nil {
		t.Fatal("another tenant's principal was added to this group")
	}
}

func scimGroupPatch(t *testing.T, op, path string, members ...string) string {
	t.Helper()

	operation := map[string]any{"op": op, "path": path}
	if members != nil {
		entries := make([]map[string]any, 0, len(members))
		for _, member := range members {
			entries = append(entries, map[string]any{"value": member})
		}
		operation["value"] = entries
	}
	raw, err := json.Marshal(map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{operation},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}
