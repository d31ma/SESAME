package identity

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// These are the Phase 3 exit-gate properties: default deny, precedence,
// missing attributes, tenant isolation, and version pinning. Each runs over
// pseudo-random inputs from a fixed seed so a failure is reproducible.

const propertyIterations = 300

func propertySource() *rand.Rand {
	return rand.New(rand.NewPCG(0x5E5A_4D45, 0x9E3779B9))
}

func randomSegment(source *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	length := 1 + source.IntN(6)
	segment := make([]byte, length)
	for index := range segment {
		segment[index] = alphabet[source.IntN(len(alphabet))]
	}
	return string(segment)
}

func randomValue(source *rand.Rand) string {
	return randomSegment(source) + ":" + randomSegment(source)
}

// TestPropertyDefaultDeny asserts no random request is ever allowed in a
// tenant that has a principal but no grants at all.
func TestPropertyDefaultDeny(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	principal, err := service.PrincipalCreate(context.Background(), tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "nobody@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	source := propertySource()
	for iteration := range propertyIterations {
		decision, err := service.Decide(DecisionRequest{
			TenantID:    tenantID,
			PrincipalID: principal.ID,
			Action:      randomValue(source),
			Resource:    randomValue(source),
		}, nil)
		if err != nil {
			t.Fatalf("iteration %d: Decide() error = %v", iteration, err)
		}
		if decision.Decision != DecisionDeny || decision.ReasonCode != ReasonDenyNoGrant {
			t.Fatalf("iteration %d: ungranted request produced %#v", iteration, decision)
		}
	}
}

// TestPropertyPrecedence asserts a permission allows exactly the values its
// patterns match, and nothing else: an allow implies a match, and a match
// implies an allow.
func TestPropertyPrecedence(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	principal, err := service.PrincipalCreate(context.Background(), tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "grantee@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	permission := authzdomain.Permission{Action: "doc:read", Resource: "project:*"}
	role, err := service.RoleCreate(context.Background(), tenantID, "precedence",
		[]authzdomain.Permission{permission}, "test")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	if _, err := service.GrantCreate(context.Background(), tenantID, principal.ID, role.ID, "test"); err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}

	source := propertySource()
	for iteration := range propertyIterations {
		action := "doc:read"
		resource := "project:" + randomSegment(source)
		// Half the iterations deliberately fall outside the patterns.
		if iteration%2 == 0 {
			action = randomValue(source)
			resource = randomValue(source)
		}
		decision, err := service.Decide(DecisionRequest{
			TenantID:    tenantID,
			PrincipalID: principal.ID,
			Action:      action,
			Resource:    resource,
		}, nil)
		if err != nil {
			t.Fatalf("iteration %d: Decide() error = %v", iteration, err)
		}
		matched := authzdomain.Matches(permission.Action, action) &&
			authzdomain.Matches(permission.Resource, resource)
		allowed := decision.Decision == DecisionAllow
		if matched != allowed {
			t.Fatalf(
				"iteration %d: %s on %s matched=%t but allowed=%t",
				iteration, action, resource, matched, allowed,
			)
		}
	}
}

// TestPropertyMissingAttributes asserts a conditioned permission allows only
// when every required attribute is supplied with the exact value, that an
// absent attribute is reported by name, and that the name is an attribute
// key rather than any request or policy value.
func TestPropertyMissingAttributes(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	principal, err := service.PrincipalCreate(context.Background(), tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "conditional@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	conditions := map[string]string{"channel": "internal", "mfa": "true"}
	role, err := service.RoleCreate(context.Background(), tenantID, "conditional", []authzdomain.Permission{
		{Action: "deploy:run", Resource: "env:*", Conditions: conditions},
	}, "test")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	if _, err := service.GrantCreate(context.Background(), tenantID, principal.ID, role.ID, "test"); err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}

	source := propertySource()
	for iteration := range propertyIterations {
		supplied := map[string]string{}
		for key, value := range conditions {
			switch source.IntN(3) {
			case 0: // omit
			case 1:
				supplied[key] = value
			default:
				supplied[key] = randomSegment(source)
			}
		}
		decision, err := service.Decide(DecisionRequest{
			TenantID:    tenantID,
			PrincipalID: principal.ID,
			Action:      "deploy:run",
			Resource:    "env:staging",
			Context:     supplied,
		}, nil)
		if err != nil {
			t.Fatalf("iteration %d: Decide() error = %v", iteration, err)
		}

		// A missing attribute is only reported when supplying it would
		// change the outcome: every supplied value must already match.
		complete, mismatched := true, false
		for key, required := range conditions {
			value, present := supplied[key]
			switch {
			case !present:
				complete = false
			case value != required:
				mismatched = true
			}
		}
		exact := complete && !mismatched

		switch {
		case exact:
			if decision.Decision != DecisionAllow {
				t.Fatalf("iteration %d: exact context denied: %#v (%v)", iteration, decision, supplied)
			}
		case !complete && !mismatched:
			if decision.ReasonCode != ReasonDenyMissingContext {
				t.Fatalf("iteration %d: incomplete context gave %#v (%v)", iteration, decision, supplied)
			}
			if _, isCondition := conditions[decision.MissingKey]; !isCondition {
				t.Fatalf("iteration %d: missing key %q is not a condition key", iteration, decision.MissingKey)
			}
			if _, present := supplied[decision.MissingKey]; present {
				t.Fatalf("iteration %d: reported %q missing but it was supplied", iteration, decision.MissingKey)
			}
		default:
			if decision.Decision != DecisionDeny || decision.ReasonCode != ReasonDenyNoGrant {
				t.Fatalf("iteration %d: wrong value gave %#v (%v)", iteration, decision, supplied)
			}
			if decision.MissingKey != "" {
				t.Fatalf("iteration %d: wrong value named a missing key %q", iteration, decision.MissingKey)
			}
		}
	}
}

// TestPropertyTenantIsolation asserts a grant in one tenant never allows the
// same principal ID in another tenant, in either direction.
func TestPropertyTenantIsolation(t *testing.T) {
	t.Parallel()

	service, _, leftTenant := bootstrapService(t)
	right, err := service.Bootstrap(context.Background(), "right", "test")
	if err != nil {
		t.Fatalf("Bootstrap(right) error = %v", err)
	}

	principal, err := service.PrincipalCreate(context.Background(), leftTenant, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "left@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	role, err := service.RoleCreate(context.Background(), leftTenant, "everything", []authzdomain.Permission{
		{Action: "*", Resource: "*"},
	}, "test")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	if _, err := service.GrantCreate(context.Background(), leftTenant, principal.ID, role.ID, "test"); err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}

	source := propertySource()
	for iteration := range propertyIterations {
		action, resource := randomValue(source), randomValue(source)

		allowed, err := service.Decide(DecisionRequest{
			TenantID:    leftTenant,
			PrincipalID: principal.ID,
			Action:      action,
			Resource:    resource,
		}, nil)
		if err != nil || allowed.Decision != DecisionAllow {
			t.Fatalf("iteration %d: own-tenant decision = %#v, %v", iteration, allowed, err)
		}

		crossed, err := service.Decide(DecisionRequest{
			TenantID:    right.Tenant.ID,
			PrincipalID: principal.ID,
			Action:      action,
			Resource:    resource,
		}, nil)
		if err != nil {
			t.Fatalf("iteration %d: cross-tenant Decide() error = %v", iteration, err)
		}
		if crossed.Decision != DecisionDeny || crossed.ReasonCode != ReasonDenyPrincipalNotFound {
			t.Fatalf("iteration %d: cross-tenant decision = %#v", iteration, crossed)
		}
	}
}

// TestPropertyVersionPinning asserts a pinned version either answers at
// exactly that version or fails closed, never at a different one, and that
// every policy change moves the version forward.
func TestPropertyVersionPinning(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	principal, err := service.PrincipalCreate(context.Background(), tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "pinned@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	request := DecisionRequest{
		TenantID:    tenantID,
		PrincipalID: principal.ID,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}

	source := propertySource()
	previous := service.PolicyVersion()
	for iteration := range 60 {
		// Every few iterations, add a policy event and require the version
		// to advance.
		if iteration%3 == 0 {
			if _, err := service.RoleCreate(context.Background(), tenantID,
				fmt.Sprintf("role-%d", iteration), []authzdomain.Permission{
					{Action: "doc:read", Resource: "project:*"},
				}, "test"); err != nil {
				t.Fatalf("iteration %d: RoleCreate() error = %v", iteration, err)
			}
			current := service.PolicyVersion()
			if current <= previous {
				t.Fatalf("iteration %d: policy version did not advance (%d -> %d)", iteration, previous, current)
			}
			previous = current
		}

		current := service.PolicyVersion()
		pinned, err := service.Decide(request, &current)
		if err != nil {
			t.Fatalf("iteration %d: current pin failed: %v", iteration, err)
		}
		if pinned.PolicyVersion != current {
			t.Fatalf("iteration %d: pinned answer at version %d, want %d", iteration, pinned.PolicyVersion, current)
		}

		offset := int64(1 + source.IntN(5))
		if source.IntN(2) == 0 {
			offset = -offset
		}
		other := current + offset
		if other == current {
			continue
		}
		if _, err := service.Decide(request, &other); !errors.Is(err, ErrStalePolicyVersion) {
			t.Fatalf("iteration %d: pin at %d returned %v, want ErrStalePolicyVersion", iteration, other, err)
		}
	}
}
