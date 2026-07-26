package identity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// GoldenCorpus mirrors api/machine/v1/decisions.golden.json. The Go, Node,
// and Python SDK suites build the same fixture from the same file, so the
// documented decision semantics have exactly one definition.
type GoldenCorpus struct {
	Setup struct {
		Tenant      string `json:"tenant"`
		OtherTenant string `json:"other_tenant"`
		Principals  []struct {
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Value     string `json:"value"`
		} `json:"principals"`
		Roles []struct {
			Name        string                   `json:"name"`
			Permissions []authzdomain.Permission `json:"permissions"`
		} `json:"roles"`
		Groups []struct {
			Name    string   `json:"name"`
			Members []string `json:"members"`
		} `json:"groups"`
		Grants []struct {
			Role      string `json:"role"`
			Principal string `json:"principal"`
			Group     string `json:"group"`
		} `json:"grants"`
		Suspended []string `json:"suspended"`
	} `json:"setup"`
	Cases []struct {
		Name        string            `json:"name"`
		Principal   string            `json:"principal"`
		PrincipalID string            `json:"principal_id"`
		Tenant      string            `json:"tenant"`
		TenantID    string            `json:"tenant_id"`
		Action      string            `json:"action"`
		Resource    string            `json:"resource"`
		Context     map[string]string `json:"context"`
		Decision    string            `json:"decision"`
		ReasonCode  string            `json:"reason_code"`
		MissingKey  string            `json:"missing_context_key"`
	} `json:"cases"`
}

// LoadGoldenCorpus reads the shared decision fixture.
func LoadGoldenCorpus(t *testing.T) GoldenCorpus {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate golden corpus test file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	encoded, err := os.ReadFile(filepath.Join(root, "api", "machine", "v1", "decisions.golden.json"))
	if err != nil {
		t.Fatalf("read golden corpus: %v", err)
	}
	var corpus GoldenCorpus
	if err := json.Unmarshal(encoded, &corpus); err != nil {
		t.Fatalf("decode golden corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("golden corpus has no cases")
	}
	return corpus
}

func TestGoldenDecisionCorpusFixture(t *testing.T) {
	t.Parallel()

	corpus := LoadGoldenCorpus(t)
	service, err := New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()

	tenant, err := service.Bootstrap(ctx, corpus.Setup.Tenant, "golden")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	otherTenant, err := service.Bootstrap(ctx, corpus.Setup.OtherTenant, "golden")
	if err != nil {
		t.Fatalf("Bootstrap(other) error = %v", err)
	}

	principals := map[string]string{}
	for _, wanted := range corpus.Setup.Principals {
		created, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, wanted.Kind, principaldomain.Identifier{
			Namespace: wanted.Namespace,
			Value:     wanted.Value,
		}, "golden")
		if err != nil {
			t.Fatalf("PrincipalCreate(%s) error = %v", wanted.Name, err)
		}
		principals[wanted.Name] = created.ID
	}
	roles := map[string]string{}
	for _, wanted := range corpus.Setup.Roles {
		created, err := service.RoleCreate(ctx, tenant.Tenant.ID, wanted.Name, wanted.Permissions, "golden")
		if err != nil {
			t.Fatalf("RoleCreate(%s) error = %v", wanted.Name, err)
		}
		roles[wanted.Name] = created.ID
	}
	groups := map[string]string{}
	for _, wanted := range corpus.Setup.Groups {
		created, err := service.GroupCreate(ctx, tenant.Tenant.ID, wanted.Name, "golden")
		if err != nil {
			t.Fatalf("GroupCreate(%s) error = %v", wanted.Name, err)
		}
		groups[wanted.Name] = created.ID
		for _, member := range wanted.Members {
			if err := service.GroupMemberAdd(ctx, created.ID, principals[member], "golden"); err != nil {
				t.Fatalf("GroupMemberAdd(%s) error = %v", member, err)
			}
		}
	}
	for _, wanted := range corpus.Setup.Grants {
		var err error
		if wanted.Group != "" {
			_, err = service.GrantCreateForGroup(ctx, tenant.Tenant.ID, groups[wanted.Group], roles[wanted.Role], "golden")
		} else {
			_, err = service.GrantCreate(ctx, tenant.Tenant.ID, principals[wanted.Principal], roles[wanted.Role], "golden")
		}
		if err != nil {
			t.Fatalf("grant %s error = %v", wanted.Role, err)
		}
	}
	for _, name := range corpus.Setup.Suspended {
		if _, err := service.PrincipalSuspend(ctx, principals[name], "golden"); err != nil {
			t.Fatalf("PrincipalSuspend(%s) error = %v", name, err)
		}
	}

	for _, test := range corpus.Cases {
		request := DecisionRequest{
			TenantID:    tenant.Tenant.ID,
			PrincipalID: principals[test.Principal],
			Action:      test.Action,
			Resource:    test.Resource,
			Context:     test.Context,
		}
		if test.PrincipalID != "" {
			request.PrincipalID = test.PrincipalID
		}
		if test.Tenant == "other" {
			request.TenantID = otherTenant.Tenant.ID
		}
		if test.TenantID != "" {
			request.TenantID = test.TenantID
		}

		decision, err := service.Decide(request, nil)
		if err != nil {
			t.Fatalf("%s: Decide() error = %v", test.Name, err)
		}
		if decision.Decision != test.Decision || decision.ReasonCode != test.ReasonCode {
			t.Fatalf(
				"%s: decision = %s/%s, want %s/%s",
				test.Name,
				decision.Decision,
				decision.ReasonCode,
				test.Decision,
				test.ReasonCode,
			)
		}
		if decision.MissingKey != test.MissingKey {
			t.Fatalf(
				"%s: missing_context_key = %q, want %q",
				test.Name,
				decision.MissingKey,
				test.MissingKey,
			)
		}
	}
}
