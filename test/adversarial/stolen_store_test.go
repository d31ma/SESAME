package adversarial_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The stolen-database question: an attacker walks off with the FYLO data root
// and the snapshots, but not the deployment key directory. What can they use?
//
// Every individual answer is already argued in the code — passwords are
// Argon2id, session secrets are stored as digests, TOTP secrets are sealed
// under a key that lives outside FYLO. Arguing it per field is not the same as
// checking it, and the gap between the two is where a future change lands a
// plaintext secret in an event payload that nobody notices.
//
// So this plants a distinctive value for every credential type SESAME holds,
// exercises the flows that persist them, and then reads every byte under the
// deployment looking for them.

// distinctive values, chosen so a match cannot be coincidence.
const (
	plantedPassword = "canary-password-6f2a1c9e4b7d"
)

// walkDeployment returns every regular file under the deployment, so the sweep
// covers the FYLO root, its version-control object store, snapshots, and
// anything else a thief would carry away with the directory.
func walkDeployment(t *testing.T, root string) map[string][]byte {
	t.Helper()

	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, _ := filepath.Rel(root, path)
		files[relative] = content
		return nil
	})
	if err != nil {
		t.Fatalf("walk the deployment: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("the deployment contains no files; the sweep would prove nothing")
	}
	return files
}

// findPlaintext reports which files contain a value verbatim.
func findPlaintext(files map[string][]byte, needle string) []string {
	var hits []string
	for name, content := range files {
		if strings.Contains(string(content), needle) {
			hits = append(hits, name)
		}
	}
	return hits
}

// TestStolenDataRootYieldsNoUsableCredential is the load-bearing claim: an
// attacker holding the store holds no credential they can present.
func TestStolenDataRootYieldsNoUsableCredential(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// A password of our choosing, so a match in the store is unambiguous.
	if err := deploy.client.SetPassword(ctx, deploy.principalID, plantedPassword); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	// A session, whose secret is returned once and stored as a digest.
	transaction, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID, deploy.identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := deploy.client.AuthenticationVerifyPassword(ctx,
		transaction.TransactionID, plantedPassword); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := deploy.client.AuthenticationComplete(ctx, transaction.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	// A TOTP shared secret, which unlike a password must be readable to
	// verify a code — so it is sealed rather than hashed.
	enrolment, err := deploy.client.TOTPEnroll(ctx, deploy.principalID, "Canary")
	if err != nil {
		t.Fatalf("TOTPEnroll() error = %v", err)
	}

	// Recovery codes, stored as digests.
	recovery, err := deploy.client.RecoveryCodesIssue(ctx, deploy.principalID)
	if err != nil {
		t.Fatalf("RecoveryCodesIssue() error = %v", err)
	}
	if len(recovery.Codes) == 0 {
		t.Fatal("no recovery codes were issued")
	}

	// An OIDC client secret, plus a full code exchange so an authorization
	// code, an access token, and a refresh token all touch the store.
	redirect := deploy.authorize(t, session)
	tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(redirect.Code))
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	files := walkDeployment(t, deploy.directory)

	// Everything an attacker could present to impersonate somebody.
	secrets := map[string]string{
		"the password":            plantedPassword,
		"the session secret":      session.Secret,
		"the TOTP shared secret":  enrolment.Secret,
		"the first recovery code": recovery.Codes[0],
		"the OIDC client secret":  deploy.secret,
		"the authorization code":  redirect.Code,
		"the access token":        tokens.AccessToken,
		"the refresh token":       tokens.RefreshToken,
	}
	for name, secret := range secrets {
		if secret == "" {
			t.Errorf("%s is empty; the sweep would pass without proving anything", name)
			continue
		}
		if hits := findPlaintext(files, secret); len(hits) > 0 {
			t.Errorf("%s appears verbatim in the stolen store: %v", name, hits)
		}
	}
	t.Logf("swept %d files for %d planted credentials", len(files), len(secrets))
}

// TestStolenDataRootStillExposesWhoIsThere is the other half of the honest
// answer, and it asserts a weakness on purpose.
//
// Credentials survive theft; personal data does not. Identifiers, tenant and
// group names, and the audit trail are stored in the clear, because the engine
// has to query and project them. A thief learns who has an account, which
// tenant they belong to, and when they signed in — and this test exists so
// that fact is stated by the suite rather than discovered by a reader.
//
// If SESAME ever adopts encryption at rest for these fields, this test should
// fail and be rewritten. That is the point.
func TestStolenDataRootStillExposesWhoIsThere(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	files := walkDeployment(t, deploy.directory)

	hits := findPlaintext(files, deploy.identifier.Value)
	if len(hits) == 0 {
		t.Fatalf("the identifier %q was not found in the store — if it is now "+
			"encrypted at rest, this test and the documented threat model both "+
			"need rewriting", deploy.identifier.Value)
	}
	t.Logf("the identifier %q appears in %d files, in the clear, as documented",
		deploy.identifier.Value, len(hits))
}
