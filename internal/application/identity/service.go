// Package identity implements tenant and principal lifecycle commands and
// queries over the security-event ledger.
package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	federationdomain "github.com/d31ma/sesame/internal/domain/federation"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	samldomain "github.com/d31ma/sesame/internal/domain/saml"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// decoyPassword is hashed once per process to give unresolved identifiers a
// verifier of the right shape. It authenticates nobody: no principal can
// hold it, because a transaction with no principal can never succeed.
const decoyPassword = "sesame decoy verifier, matches no principal"

// Ledger appends durable security events. It is implemented by the FYLO
// security ledger and by in-memory fakes in tests.
type Ledger interface {
	Append(
		ctx context.Context,
		eventType string,
		tenantID string,
		actor string,
		payload any,
	) (audit.Event, error)
}

// SnapshotWriter durably records verified projection checkpoints. It is
// optional; without it the complete ledger replays at every open.
type SnapshotWriter interface {
	WriteSnapshot(ctx context.Context, state any) error
}

// State is the versioned projection payload stored inside snapshots.
type State struct {
	SchemaVersion int                              `json:"schema_version"`
	Tenants       []tenantdomain.Tenant            `json:"tenants"`
	Principals    []principaldomain.Principal      `json:"principals,omitempty"`
	Roles         []authzdomain.Role               `json:"roles,omitempty"`
	Grants        []authzdomain.Grant              `json:"grants,omitempty"`
	Groups        []authzdomain.Group              `json:"groups,omitempty"`
	Memberships   []authzdomain.GroupMemberPayload `json:"memberships,omitempty"`
	PolicyVersion int64                            `json:"policy_version,omitempty"`
	// Authentication state. Verifiers are one-way and sessions carry only
	// secret digests, so a snapshot never holds a usable credential — but
	// it must carry these projections or a snapshot-seeded restart would
	// silently forget every password and session.
	Passwords    []PasswordState           `json:"passwords,omitempty"`
	TOTP         []TOTPState               `json:"totp,omitempty"`
	Recovery     []RecoveryState           `json:"recovery,omitempty"`
	Sessions     []sessiondomain.Session   `json:"sessions,omitempty"`
	Transactions []authndomain.Transaction `json:"transactions,omitempty"`
	Clients      []ClientState             `json:"clients,omitempty"`
	// Interactions carry only digests of their handle secret and code, so a
	// snapshot never holds a redeemable authorization code. The same is true
	// of refresh tokens; the family carries no token material at all.
	Interactions    []oidcdomain.Interaction   `json:"interactions,omitempty"`
	RefreshFamilies []oidcdomain.RefreshFamily `json:"refresh_families,omitempty"`
	RefreshTokens   []oidcdomain.RefreshToken  `json:"refresh_tokens,omitempty"`
	Consents        []oidcdomain.Consent       `json:"consents,omitempty"`
	// Passkeys carry a public key and a sign counter. The counter must
	// travel or a restore would silently disable clone detection.
	Passkeys []authenticatordomain.Passkey `json:"passkeys,omitempty"`
	// Federation state. Providers must travel or a snapshot-seeded restart
	// would forget every registered issuer and refuse every federated
	// login. Links must travel for the same reason: a principal would lose
	// the external subject that identifies them.
	Providers       []ProviderState          `json:"providers,omitempty"`
	FederatedLogins []federationdomain.Login `json:"federated_logins,omitempty"`
	FederatedLinks  []FederatedLinkState     `json:"federated_links,omitempty"`
	// Provisioning state. Token digests must travel or every provisioning
	// client would silently stop authenticating after a restart.
	SCIMClients []SCIMClientState `json:"scim_clients,omitempty"`
	SCIMUsers   []SCIMUserState   `json:"scim_users,omitempty"`
	// SAML state. The replay claims must travel: an assertion spent before
	// a restart and forgotten after one can be replayed.
	// Pushed requests travel so their single-use claim survives a restart.
	PushedRequests []PushedRequestState `json:"pushed_requests,omitempty"`
	DPoPProofs     []DPoPProofState     `json:"dpop_proofs,omitempty"`
	// Device grants travel: a device polls across restarts by definition.
	DeviceAuthorizations []DeviceAuthorizationState `json:"device_authorizations,omitempty"`
	SAMLProviders        []SAMLProviderState        `json:"saml_providers,omitempty"`
	SAMLLogins           []samlLogin                `json:"saml_logins,omitempty"`
	SAMLLinks            []SAMLLinkState            `json:"saml_links,omitempty"`
	SAMLReplay           []string                   `json:"saml_replay,omitempty"`
}

// ProviderState is one registered external provider in a snapshot. The
// client secret travels sealed, exactly as it sits in the ledger; validated
// metadata and keys do not, because they are refetchable and a stale copy
// would be worse than an absent one.
type ProviderState struct {
	Provider     federationdomain.Provider `json:"provider"`
	SecretSealed string                    `json:"secret_sealed,omitempty"`
	// SecretsSealed carries each in-flight login's sealed state, nonce, and
	// verifier, keyed by login ID, so a restart mid-login can still complete
	// the exchange.
}

// FederatedLinkState binds an external subject hash to a principal.
type FederatedLinkState struct {
	SubjectHash string `json:"subject_hash"`
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
}

// ClientState is one registered OIDC client in a snapshot. The secret is a
// one-way verifier, so a snapshot never holds a usable client secret.
type ClientState struct {
	Client         oidcdomain.Client `json:"client"`
	SecretVerifier string            `json:"secret_verifier,omitempty"`
}

// TOTPState is one stored TOTP authenticator in a snapshot. The secret is
// sealed, so a snapshot never holds a usable shared secret.
type TOTPState struct {
	PrincipalID  string `json:"principal_id"`
	SealedSecret string `json:"sealed_secret"`
	Active       bool   `json:"active"`
	LastCounter  int64  `json:"last_counter"`
}

// RecoveryState is one principal's unspent recovery-code digests in a
// snapshot. Digests are one-way, so a snapshot never holds a usable code.
type RecoveryState struct {
	PrincipalID string   `json:"principal_id"`
	Unspent     []string `json:"unspent"`
}

// PasswordState is one stored Argon2id verifier in a snapshot.
type PasswordState struct {
	PrincipalID string `json:"principal_id"`
	Verifier    string `json:"verifier"`
}

// StateSchemaVersion is the current snapshot state schema.
const StateSchemaVersion = 1

// ErrNotFound reports a query for a tenant that does not exist.
var ErrNotFound = errors.New("tenant not found")

// ErrPrincipalNotFound reports a query for a principal that does not exist.
var ErrPrincipalNotFound = errors.New("principal not found")

// ErrIdentifierConflict reports an identifier already claimed inside its
// tenant and namespace.
var ErrIdentifierConflict = errors.New("identifier is already claimed")

// ErrReadOnly reports a command issued against a projection built without a
// ledger. Such a service can answer queries and decisions but must never
// pretend to record a security transition.
var ErrReadOnly = errors.New("identity service is read-only: no security ledger is configured")

// ErrStorageFailure marks a command that failed at the persistence boundary.
// Bootstrap is idempotent per normalized name, so callers may retry after a
// storage failure.
var ErrStorageFailure = errors.New("security ledger unavailable")

// BootstrapResult reports the outcome of a bootstrap command.
type BootstrapResult struct {
	Tenant  tenantdomain.Tenant `json:"tenant"`
	Created bool                `json:"created"`
}

// Service coordinates tenant commands for one single-writer deployment.
// ponytail: the coordinator is one mutex; a queued coordinator arrives when a
// second command family needs fairness or backpressure.
type Service struct {
	ledger    Ledger
	snapshots SnapshotWriter
	logger    *slog.Logger

	mu     sync.Mutex
	byName map[string]tenantdomain.Tenant
	byID   map[string]tenantdomain.Tenant
	// principals is keyed by principal ID; identifiers maps the
	// tenant/namespace/value claim key to the owning principal ID.
	principals  map[string]principaldomain.Principal
	identifiers map[string]string
	// roles and grants are keyed by public ID; roleNames and grantKeys hold
	// the uniqueness claims. policyVersion is the ledger sequence of the
	// latest policy-affecting event.
	roles         map[string]authzdomain.Role
	roleNames     map[string]string
	grants        map[string]authzdomain.Grant
	grantKeys     map[string]string
	groups        map[string]authzdomain.Group
	groupNames    map[string]string
	memberships   map[string]map[string]struct{}
	policyVersion int64
	// passwords holds Argon2id verifiers by principal ID; transactions and
	// sessions hold authentication state. None of these ever carries a
	// plaintext credential.
	passwords    map[string]string
	totp         map[string]totpAuthenticator
	recovery     map[string]recoveryCodes
	transactions map[string]authndomain.Transaction
	sessions     map[string]sessiondomain.Session
	// clients holds registered relying parties by public ID; clientNames
	// holds the per-tenant name uniqueness claim.
	clients     map[string]oidcClient
	clientNames map[string]string
	// scimClients holds provisioning clients by public ID, with the digest
	// of their bearer token. scimUsers holds the SCIM record attached to a
	// principal; the principal's own status remains the source of truth for
	// whether that user is active.
	scimClients map[string]provisioningClient
	scimUsers   map[string]scimUser
	// samlProviders holds registered SAML identity providers with their
	// parsed certificates; samlLogins holds in-flight authentications;
	// samlLinks maps a subject hash to its principal; samlReplay records
	// spent assertions so a restart cannot forget one was used.
	samlProviders map[string]samlProvider
	samlLogins    map[string]samlLogin
	samlLinks     map[string]string
	samlReplay    map[string]struct{}
	// providers holds registered external identity providers by public ID,
	// with their validated metadata and keys. Metadata is derived and
	// refetchable; the registered issuer stays authoritative.
	providers map[string]federationProvider
	// federatedLogins holds in-flight federated authentications by public
	// ID; federatedSecrets holds their sealed state, nonce, and PKCE
	// verifier. federatedLinks maps an external subject hash to the
	// principal that claims it.
	federatedLogins  map[string]federationdomain.Login
	federatedSecrets map[string]string
	federatedLinks   map[string]string
	// interactions holds browser-facing authorization flows by public ID.
	// They carry only digests of their handle secret and code.
	interactions map[string]oidcdomain.Interaction
	// refreshTokens and refreshFamilies hold rotating refresh state. Tokens
	// carry only digests; the family is the unit revocation acts on.
	refreshTokens   map[string]oidcdomain.RefreshToken
	refreshFamilies map[string]oidcdomain.RefreshFamily
	// dpopProofs holds spent DPoP proof identifiers for the length of one
	// proof window, which is what makes a replayed proof detectable.
	dpopProofs map[string]dpopProofRecord

	// pushedRequests holds authorization requests validated on the back
	// channel and awaiting a browser, by public ID.
	pushedRequests map[string]oidcdomain.PushedRequest
	// deviceAuthorizations holds device grants by public ID. A device polls
	// against one of these, so it must survive a restart with its state.
	deviceAuthorizations map[string]oidcdomain.DeviceAuthorization
	// consents holds standing user agreements, keyed by principal and client.
	consents map[string]oidcdomain.Consent
	// passkeys holds registered WebAuthn credentials by credential ID. Only
	// public keys and counters are stored.
	passkeys map[string]authenticatordomain.Passkey
	// passkeyChallenges holds outstanding registration challenges. They are
	// in-memory on purpose: a lost nonce costs a retry, and a durable one
	// would put an event in the ledger for every abandoned registration.
	passkeyChallenges map[string]pendingPasskeyChallenge
	// issuer identifies this deployment in the tokens it mints. Token
	// issuance fails closed without it.
	issuer string
	// secretsKey seals credentials that must be read back, such as TOTP
	// shared secrets. Without it those commands fail closed.
	secretsKey []byte
	// signingKey mints tokens for relying parties. It is never projected
	// from the ledger: it comes from the deployment key directory, so a
	// FYLO data root alone cannot sign.
	signingKey *tokendomain.SigningKey
	// decoyVerifier makes an unresolved identifier cost the same Argon2id
	// work as a real one, so timing does not enumerate principals.
	decoyVerifier string
	// clock is overridable in tests; production uses the wall clock.
	clock func() time.Time
}

// requireLedger guards every command path. Without it a read-only
// projection would panic on the first write instead of refusing it.
func (s *Service) requireLedger() error {
	if s.ledger == nil {
		return ErrReadOnly
	}
	return nil
}

func (s *Service) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now().UTC()
}

// UseClock replaces the wall clock, for tests that need expiry to be
// deterministic.
func (s *Service) UseClock(clock func() time.Time) {
	s.clock = clock
}

func identifierKey(tenantID, namespace, value string) string {
	return tenantID + "\x00" + namespace + "\x00" + value
}

// New builds the tenant projection from replayed ledger events. Event types
// other than tenant events are skipped here; the ledger has already rejected
// unregistered types during replay. Tenant events themselves must decode
// exactly.
func New(ledger Ledger, events []audit.Event) (*Service, error) {
	return NewFromSnapshot(ledger, nil, events)
}

// NewFromSnapshot seeds the projection from a verified snapshot state and
// applies the verified tail events after it. A nil snapshot state is a
// complete replay.
func NewFromSnapshot(
	ledger Ledger,
	snapshotState json.RawMessage,
	tail []audit.Event,
) (*Service, error) {
	service := &Service{
		ledger:               ledger,
		logger:               slog.New(slog.DiscardHandler),
		byName:               make(map[string]tenantdomain.Tenant),
		byID:                 make(map[string]tenantdomain.Tenant),
		principals:           make(map[string]principaldomain.Principal),
		identifiers:          make(map[string]string),
		roles:                make(map[string]authzdomain.Role),
		roleNames:            make(map[string]string),
		grants:               make(map[string]authzdomain.Grant),
		grantKeys:            make(map[string]string),
		groups:               make(map[string]authzdomain.Group),
		groupNames:           make(map[string]string),
		memberships:          make(map[string]map[string]struct{}),
		passwords:            make(map[string]string),
		totp:                 make(map[string]totpAuthenticator),
		recovery:             make(map[string]recoveryCodes),
		transactions:         make(map[string]authndomain.Transaction),
		sessions:             make(map[string]sessiondomain.Session),
		clients:              make(map[string]oidcClient),
		clientNames:          make(map[string]string),
		interactions:         make(map[string]oidcdomain.Interaction),
		refreshTokens:        make(map[string]oidcdomain.RefreshToken),
		refreshFamilies:      make(map[string]oidcdomain.RefreshFamily),
		consents:             make(map[string]oidcdomain.Consent),
		deviceAuthorizations: make(map[string]oidcdomain.DeviceAuthorization),
		dpopProofs:           make(map[string]dpopProofRecord),
		pushedRequests:       make(map[string]oidcdomain.PushedRequest),
		providers:            make(map[string]federationProvider),
		federatedLogins:      make(map[string]federationdomain.Login),
		federatedSecrets:     make(map[string]string),
		federatedLinks:       make(map[string]string),
		scimClients:          make(map[string]provisioningClient),
		scimUsers:            make(map[string]scimUser),
		samlProviders:        make(map[string]samlProvider),
		samlLogins:           make(map[string]samlLogin),
		samlLinks:            make(map[string]string),
		samlReplay:           make(map[string]struct{}),
		passkeys:             make(map[string]authenticatordomain.Passkey),
		passkeyChallenges:    make(map[string]pendingPasskeyChallenge),
	}
	// One decoy verifier per process: unresolved identifiers verify against
	// it so a failed lookup costs the same as a real one.
	decoy, err := authenticatordomain.NewPasswordVerifier(decoyPassword)
	if err != nil {
		return nil, fmt.Errorf("prepare authentication decoy: %w", err)
	}
	service.decoyVerifier = decoy
	if snapshotState != nil {
		var state State
		decoder := json.NewDecoder(bytes.NewReader(snapshotState))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&state); err != nil {
			return nil, fmt.Errorf("decode snapshot state: %w", err)
		}
		if state.SchemaVersion != StateSchemaVersion {
			return nil, fmt.Errorf(
				"snapshot state schema version %d; this binary supports %d",
				state.SchemaVersion,
				StateSchemaVersion,
			)
		}
		for _, restored := range state.Tenants {
			if err := service.admit(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.Principals {
			if err := service.admitPrincipal(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.Roles {
			if err := service.admitRole(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.Groups {
			if err := service.admitGroup(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.Memberships {
			members := service.memberships[restored.GroupID]
			if members == nil {
				members = make(map[string]struct{})
				service.memberships[restored.GroupID] = members
			}
			members[restored.PrincipalID] = struct{}{}
		}
		for _, restored := range state.Grants {
			if err := service.admitGrant(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		if state.PolicyVersion < 0 {
			return nil, errors.New("snapshot state has a negative policy version")
		}
		service.policyVersion = state.PolicyVersion
		for _, restored := range state.Passwords {
			if _, exists := service.principals[restored.PrincipalID]; !exists {
				return nil, fmt.Errorf("snapshot state: password for unknown principal %s", restored.PrincipalID)
			}
			service.passwords[restored.PrincipalID] = restored.Verifier
		}
		for _, restored := range state.TOTP {
			if _, exists := service.principals[restored.PrincipalID]; !exists {
				return nil, fmt.Errorf("snapshot state: TOTP for unknown principal %s", restored.PrincipalID)
			}
			service.totp[restored.PrincipalID] = totpAuthenticator{
				SealedSecret: restored.SealedSecret,
				Active:       restored.Active,
				LastCounter:  restored.LastCounter,
			}
		}
		for _, restored := range state.Recovery {
			if _, exists := service.principals[restored.PrincipalID]; !exists {
				return nil, fmt.Errorf("snapshot state: recovery codes for unknown principal %s", restored.PrincipalID)
			}
			unspent := make(map[string]struct{}, len(restored.Unspent))
			for _, digest := range restored.Unspent {
				unspent[digest] = struct{}{}
			}
			service.recovery[restored.PrincipalID] = recoveryCodes{Unspent: unspent}
		}
		for _, restored := range state.Sessions {
			if err := sessiondomain.ValidateID(restored.ID); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
			if _, exists := service.principals[restored.PrincipalID]; !exists {
				return nil, fmt.Errorf("snapshot state: session for unknown principal %s", restored.PrincipalID)
			}
			service.sessions[restored.ID] = restored
		}
		for _, restored := range state.Transactions {
			if err := authndomain.ValidateID(restored.ID); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
			service.transactions[restored.ID] = restored
		}
		// admitClient stores the record as given, so a client disabled before
		// the snapshot comes back disabled: a revocation that did not stick
		// would be worse than a slow one.
		for _, restored := range state.Clients {
			if err := service.admitClient(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		// A redeemed code must come back redeemed, or a snapshot restore
		// would hand an attacker a second use of an intercepted code. The
		// same holds for a spent refresh token, which is what makes reuse
		// detection survive a restore.
		for _, restored := range state.Interactions {
			if err := service.admitInteraction(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.RefreshFamilies {
			if err := service.admitRefreshFamily(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.RefreshTokens {
			if err := service.admitRefreshToken(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		// A withdrawn consent must come back withdrawn, or a restore would
		// re-authorize a client the user has already taken back.
		for _, restored := range state.Consents {
			if err := service.admitConsent(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.Passkeys {
			if err := service.admitPasskey(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.Providers {
			if err := service.admitProvider(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.FederatedLogins {
			service.federatedLogins[restored.ID] = restored
		}
		for _, restored := range state.FederatedLinks {
			if err := service.admitFederatedLink(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.SCIMClients {
			if err := service.admitSCIMClient(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.SCIMUsers {
			if err := service.admitSCIMUser(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.PushedRequests {
			if err := service.admitPushedRequest(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.DPoPProofs {
			if err := service.admitDPoPProof(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.DeviceAuthorizations {
			if err := service.admitDeviceAuthorization(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.SAMLProviders {
			if err := service.admitSAMLProvider(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, restored := range state.SAMLLogins {
			service.samlLogins[restored.ID] = restored
		}
		for _, restored := range state.SAMLLinks {
			if err := service.admitSAMLLink(restored); err != nil {
				return nil, fmt.Errorf("snapshot state: %w", err)
			}
		}
		for _, key := range state.SAMLReplay {
			service.samlReplay[key] = struct{}{}
		}
	}
	for _, event := range tail {
		apply, known := replayHandlers[event.Type]
		if !known {
			continue
		}
		if err := apply(service, event); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// replayHandlers maps a security-event type to the single function that
// applies it.
//
// This was a switch, and a switch made NewFromSnapshot one function of
// cyclomatic complexity 91 — a number that says "dangerously tangled" about
// what is really a lookup table. As a map, adding an event type costs one
// line and changes no control flow. The unknown-type case still falls
// through silently, exactly as the switch's absent default did: the ledger
// has already rejected unregistered types during replay, so anything
// unmatched here is a type this build does not project.
var replayHandlers = map[string]func(*Service, audit.Event) error{
	tenantdomain.EventBootstrapped:      (*Service).applyBootstrapped,
	principaldomain.EventCreated:        (*Service).applyPrincipalCreated,
	principaldomain.EventSuspended:      (*Service).applyPrincipalSuspended,
	authzdomain.EventRoleCreated:        (*Service).applyRoleCreated,
	authzdomain.EventGrantCreated:       (*Service).applyGrantCreated,
	authzdomain.EventGrantRevoked:       (*Service).applyGrantRevoked,
	authzdomain.EventGroupCreated:       (*Service).applyGroupCreated,
	authzdomain.EventGroupMemberAdded:   (*Service).applyGroupMembership,
	authzdomain.EventGroupMemberRemoved: (*Service).applyGroupMembership,
	// Both membership events project through one function; the payload
	// says which direction.
	// Both membership events project through one function; the payload
	// says which direction.
	authenticatordomain.EventPasswordSet:         (*Service).applyPasswordSet,
	authenticatordomain.EventTOTPEnrolled:        (*Service).applyTOTPEnrolled,
	authenticatordomain.EventTOTPActivated:       (*Service).applyTOTPActivated,
	authenticatordomain.EventTOTPUsed:            (*Service).applyTOTPUsed,
	authenticatordomain.EventRecoveryCodesIssued: (*Service).applyRecoveryCodesIssued,
	authenticatordomain.EventRecoveryCodeUsed:    (*Service).applyRecoveryCodeUsed,
	authenticatordomain.EventPasskeyRegistered:   (*Service).applyPasskeyRegistered,
	authenticatordomain.EventPasskeyUsed:         (*Service).applyPasskeyUsed,
	authenticatordomain.EventPasskeyRemoved:      (*Service).applyPasskeyRemoved,
	authndomain.EventStarted:                     (*Service).applyAuthenticationStarted,
	authndomain.EventFactorVerified:              (*Service).applyAuthenticationFactorVerified,
	authndomain.EventFailed:                      (*Service).applyAuthenticationFailed,
	authndomain.EventCompleted:                   (*Service).applyAuthenticationCompleted,
	sessiondomain.EventIssued:                    (*Service).applySessionIssued,
	sessiondomain.EventRevoked:                   (*Service).applySessionRevoked,
	oidcdomain.EventClientRegistered:             (*Service).applyClientRegistered,
	oidcdomain.EventClientSecretRotated:          (*Service).applyClientSecretRotated,
	oidcdomain.EventClientDisabled:               (*Service).applyClientDisabled,
	oidcdomain.EventInteractionStarted:           (*Service).applyInteractionStarted,
	oidcdomain.EventCodeIssued:                   (*Service).applyCodeIssued,
	oidcdomain.EventCodeRedeemed:                 (*Service).applyCodeRedeemed,
	oidcdomain.EventInteractionFailed:            (*Service).applyInteractionFailed,
	oidcdomain.EventRefreshIssued:                (*Service).applyRefreshIssued,
	oidcdomain.EventRefreshSpent:                 (*Service).applyRefreshSpent,
	oidcdomain.EventRefreshFamilyRevoked:         (*Service).applyRefreshFamilyRevoked,
	oidcdomain.EventConsentGranted:               (*Service).applyConsentGranted,
	oidcdomain.EventConsentWithdrawn:             (*Service).applyConsentWithdrawn,
	federationdomain.EventProviderRegistered:     (*Service).applyProviderRegistered,
	federationdomain.EventProviderDisabled:       (*Service).applyProviderDisabled,
	federationdomain.EventLoginStarted:           (*Service).applyLoginStarted,
	federationdomain.EventLoginCompleted:         (*Service).applyLoginCompleted,
	federationdomain.EventLoginFailed:            (*Service).applyLoginFailed,
	federationdomain.EventSubjectLinked:          (*Service).applySubjectLinked,
	federationdomain.EventSubjectUnlinked:        (*Service).applySubjectUnlinked,

	scimdomain.EventClientRegistered:   (*Service).applySCIMClientRegistered,
	scimdomain.EventClientTokenRotated: (*Service).applySCIMClientTokenRotated,
	scimdomain.EventClientDisabled:     (*Service).applySCIMClientDisabled,
	scimdomain.EventUserProvisioned:    (*Service).applySCIMUserProvisioned,
	scimdomain.EventUserUpdated:        (*Service).applySCIMUserUpdated,
	scimdomain.EventUserDeprovisioned:  (*Service).applySCIMUserDeprovisioned,

	oidcdomain.EventPushedRequestCreated:  (*Service).applyPushedRequestCreated,
	oidcdomain.EventPushedRequestConsumed: (*Service).applyPushedRequestConsumed,
	oidcdomain.EventDPoPProofSpent:        (*Service).applyDPoPProofSpent,

	oidcdomain.EventDeviceAuthorizationStarted:  (*Service).applyDeviceAuthorizationStarted,
	oidcdomain.EventDeviceAuthorizationApproved: (*Service).applyDeviceAuthorizationApproved,
	oidcdomain.EventDeviceAuthorizationDenied:   (*Service).applyDeviceAuthorizationDenied,
	oidcdomain.EventDeviceCodeRedeemed:          (*Service).applyDeviceCodeRedeemed,

	samldomain.EventProviderRegistered: (*Service).applySAMLProviderRegistered,
	samldomain.EventProviderDisabled:   (*Service).applySAMLProviderDisabled,
	samldomain.EventLoginStarted:       (*Service).applySAMLLoginStarted,
	samldomain.EventLoginCompleted:     (*Service).applySAMLLoginCompleted,
	samldomain.EventLoginFailed:        (*Service).applySAMLLoginFailed,
}

func decodeStrict(payload json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// UseSecretsKey supplies the key that seals recoverable credentials. It is
// set once during startup wiring, from the deployment key directory.
func (s *Service) UseSecretsKey(key []byte) {
	s.secretsKey = key
}

// UseSigningKey supplies the deployment's token signing key. It is set once
// during startup wiring; token operations fail closed without it.
func (s *Service) UseSigningKey(key *tokendomain.SigningKey) {
	s.signingKey = key
}

// SigningKeys returns the published key set. Only public material appears in
// it, so it is safe to serve unauthenticated.
func (s *Service) SigningKeys() (tokendomain.JWKS, error) {
	if s.signingKey == nil {
		return tokendomain.JWKS{}, tokendomain.ErrNoSigningKey
	}
	return tokendomain.JWKS{Keys: []tokendomain.JWK{s.signingKey.PublicJWK()}}, nil
}

// UseSnapshots enables checkpoint writes after successful commands.
func (s *Service) UseSnapshots(snapshots SnapshotWriter) {
	s.snapshots = snapshots
}

// UseLogger replaces the discard logger for operational diagnostics.
func (s *Service) UseLogger(logger *slog.Logger) {
	if logger != nil {
		s.logger = logger
	}
}

// ExportState returns the current projection as a versioned snapshot payload.
func (s *Service) ExportState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exportStateLocked()
}

func (s *Service) exportStateLocked() State {
	tenants := make([]tenantdomain.Tenant, 0, len(s.byName))
	for _, current := range s.byName {
		tenants = append(tenants, current)
	}
	sort.Slice(tenants, func(left, right int) bool {
		return tenants[left].Name < tenants[right].Name
	})
	principals := make([]principaldomain.Principal, 0, len(s.principals))
	for _, current := range s.principals {
		principals = append(principals, current)
	}
	sort.Slice(principals, func(left, right int) bool {
		return principals[left].ID < principals[right].ID
	})
	roles := make([]authzdomain.Role, 0, len(s.roles))
	for _, current := range s.roles {
		roles = append(roles, current)
	}
	sort.Slice(roles, func(left, right int) bool {
		return roles[left].ID < roles[right].ID
	})
	grants := make([]authzdomain.Grant, 0, len(s.grants))
	for _, current := range s.grants {
		grants = append(grants, current)
	}
	sort.Slice(grants, func(left, right int) bool {
		return grants[left].ID < grants[right].ID
	})
	groups := make([]authzdomain.Group, 0, len(s.groups))
	for _, current := range s.groups {
		groups = append(groups, current)
	}
	sort.Slice(groups, func(left, right int) bool {
		return groups[left].ID < groups[right].ID
	})
	memberships := make([]authzdomain.GroupMemberPayload, 0)
	for groupID, members := range s.memberships {
		for principalID := range members {
			memberships = append(memberships, authzdomain.GroupMemberPayload{
				GroupID:     groupID,
				TenantID:    s.groups[groupID].TenantID,
				PrincipalID: principalID,
			})
		}
	}
	sort.Slice(memberships, func(left, right int) bool {
		if memberships[left].GroupID != memberships[right].GroupID {
			return memberships[left].GroupID < memberships[right].GroupID
		}
		return memberships[left].PrincipalID < memberships[right].PrincipalID
	})
	passwords := make([]PasswordState, 0, len(s.passwords))
	for principalID, verifier := range s.passwords {
		passwords = append(passwords, PasswordState{PrincipalID: principalID, Verifier: verifier})
	}
	sort.Slice(passwords, func(left, right int) bool {
		return passwords[left].PrincipalID < passwords[right].PrincipalID
	})
	totpStates := make([]TOTPState, 0, len(s.totp))
	for principalID, stored := range s.totp {
		totpStates = append(totpStates, TOTPState{
			PrincipalID:  principalID,
			SealedSecret: stored.SealedSecret,
			Active:       stored.Active,
			LastCounter:  stored.LastCounter,
		})
	}
	sort.Slice(totpStates, func(left, right int) bool {
		return totpStates[left].PrincipalID < totpStates[right].PrincipalID
	})
	recoveryStates := make([]RecoveryState, 0, len(s.recovery))
	for principalID, stored := range s.recovery {
		unspent := make([]string, 0, len(stored.Unspent))
		for digest := range stored.Unspent {
			unspent = append(unspent, digest)
		}
		sort.Strings(unspent)
		recoveryStates = append(recoveryStates, RecoveryState{
			PrincipalID: principalID,
			Unspent:     unspent,
		})
	}
	sort.Slice(recoveryStates, func(left, right int) bool {
		return recoveryStates[left].PrincipalID < recoveryStates[right].PrincipalID
	})
	sessions := make([]sessiondomain.Session, 0, len(s.sessions))
	for _, current := range s.sessions {
		sessions = append(sessions, current)
	}
	sort.Slice(sessions, func(left, right int) bool {
		return sessions[left].ID < sessions[right].ID
	})
	transactions := make([]authndomain.Transaction, 0, len(s.transactions))
	for _, current := range s.transactions {
		transactions = append(transactions, current)
	}
	sort.Slice(transactions, func(left, right int) bool {
		return transactions[left].ID < transactions[right].ID
	})
	clients := make([]ClientState, 0, len(s.clients))
	for _, current := range s.clients {
		clients = append(clients, ClientState{
			Client:         current.Client,
			SecretVerifier: current.Verifier,
		})
	}
	sort.Slice(clients, func(left, right int) bool {
		return clients[left].Client.ID < clients[right].Client.ID
	})
	interactions := make([]oidcdomain.Interaction, 0, len(s.interactions))
	for _, current := range s.interactions {
		interactions = append(interactions, current)
	}
	sort.Slice(interactions, func(left, right int) bool {
		return interactions[left].ID < interactions[right].ID
	})
	refreshFamilies := make([]oidcdomain.RefreshFamily, 0, len(s.refreshFamilies))
	for _, current := range s.refreshFamilies {
		refreshFamilies = append(refreshFamilies, current)
	}
	sort.Slice(refreshFamilies, func(left, right int) bool {
		return refreshFamilies[left].ID < refreshFamilies[right].ID
	})
	refreshTokens := make([]oidcdomain.RefreshToken, 0, len(s.refreshTokens))
	for _, current := range s.refreshTokens {
		refreshTokens = append(refreshTokens, current)
	}
	sort.Slice(refreshTokens, func(left, right int) bool {
		return refreshTokens[left].ID < refreshTokens[right].ID
	})
	consents := make([]oidcdomain.Consent, 0, len(s.consents))
	for _, current := range s.consents {
		consents = append(consents, current)
	}
	sort.Slice(consents, func(left, right int) bool {
		if consents[left].PrincipalID != consents[right].PrincipalID {
			return consents[left].PrincipalID < consents[right].PrincipalID
		}
		return consents[left].ClientID < consents[right].ClientID
	})
	passkeys := make([]authenticatordomain.Passkey, 0, len(s.passkeys))
	for _, current := range s.passkeys {
		passkeys = append(passkeys, current)
	}
	sort.Slice(passkeys, func(left, right int) bool {
		return passkeys[left].CredentialID < passkeys[right].CredentialID
	})
	return State{
		SchemaVersion:        StateSchemaVersion,
		Tenants:              tenants,
		Principals:           principals,
		Roles:                roles,
		Grants:               grants,
		Groups:               groups,
		Memberships:          memberships,
		PolicyVersion:        s.policyVersion,
		Passwords:            passwords,
		TOTP:                 totpStates,
		Recovery:             recoveryStates,
		Sessions:             sessions,
		Transactions:         transactions,
		Clients:              clients,
		Interactions:         interactions,
		RefreshFamilies:      refreshFamilies,
		RefreshTokens:        refreshTokens,
		Consents:             consents,
		Passkeys:             passkeys,
		Providers:            s.exportProvidersLocked(),
		FederatedLogins:      s.exportFederatedLoginsLocked(),
		FederatedLinks:       s.exportFederatedLinksLocked(),
		SCIMClients:          s.exportSCIMClientsLocked(),
		SCIMUsers:            s.exportSCIMUsersLocked(),
		PushedRequests:       s.exportPushedRequestsLocked(),
		DPoPProofs:           s.exportDPoPProofsLocked(),
		DeviceAuthorizations: s.exportDeviceAuthorizationsLocked(),
		SAMLProviders:        s.exportSAMLProvidersLocked(),
		SAMLLogins:           s.exportSAMLLoginsLocked(),
		SAMLLinks:            s.exportSAMLLinksLocked(),
		SAMLReplay:           s.exportSAMLReplayLocked(),
	}
}

// Bootstrap creates the named tenant exactly once. Repeating the command with
// the same normalized name returns the existing tenant without appending a
// second event.
func (s *Service) Bootstrap(ctx context.Context, name, actor string) (BootstrapResult, error) {
	if err := s.requireLedger(); err != nil {
		return BootstrapResult{}, err
	}
	normalized := tenantdomain.NormalizeName(name)
	if err := tenantdomain.ValidateName(normalized); err != nil {
		return BootstrapResult{}, err
	}
	if actor == "" {
		return BootstrapResult{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, exists := s.byName[normalized]; exists {
		return BootstrapResult{Tenant: existing, Created: false}, nil
	}

	id, err := tenantdomain.NewID()
	if err != nil {
		return BootstrapResult{}, err
	}
	created := tenantdomain.Tenant{
		ID:     id,
		Name:   normalized,
		Status: tenantdomain.StatusActive,
	}
	event, err := s.ledger.Append(ctx, tenantdomain.EventBootstrapped, id, actor, tenantdomain.BootstrappedPayload{
		TenantID: id,
		Name:     normalized,
		Status:   tenantdomain.StatusActive,
	})
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyBootstrapped(event); err != nil {
		return BootstrapResult{}, err
	}

	s.writeSnapshotLocked(ctx, id)
	return BootstrapResult{Tenant: created, Created: true}, nil
}

// GetByID returns one tenant by public identifier.
func (s *Service) GetByID(id string) (tenantdomain.Tenant, error) {
	if err := tenantdomain.ValidateID(id); err != nil {
		return tenantdomain.Tenant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found, exists := s.byID[id]
	if !exists {
		return tenantdomain.Tenant{}, ErrNotFound
	}
	return found, nil
}

// GetByName returns one tenant by normalized name.
func (s *Service) GetByName(name string) (tenantdomain.Tenant, error) {
	normalized := tenantdomain.NormalizeName(name)
	if err := tenantdomain.ValidateName(normalized); err != nil {
		return tenantdomain.Tenant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found, exists := s.byName[normalized]
	if !exists {
		return tenantdomain.Tenant{}, ErrNotFound
	}
	return found, nil
}

func (s *Service) applyBootstrapped(event audit.Event) error {
	var payload tenantdomain.BootstrappedPayload
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := s.admit(tenantdomain.Tenant{
		ID:     payload.TenantID,
		Name:   payload.Name,
		Status: payload.Status,
	}); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	return nil
}

// PrincipalCreate registers one principal and atomically claims its first
// identifier: the claim and the principal are one security event, so replay
// cannot separate them.
func (s *Service) PrincipalCreate(
	ctx context.Context,
	tenantID string,
	kind string,
	identifier principaldomain.Identifier,
	actor string,
) (principaldomain.Principal, error) {
	if err := s.requireLedger(); err != nil {
		return principaldomain.Principal{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return principaldomain.Principal{}, err
	}
	if err := principaldomain.ValidateKind(kind); err != nil {
		return principaldomain.Principal{}, err
	}
	identifier.Value = principaldomain.NormalizeIdentifier(identifier.Value)
	if err := principaldomain.ValidateIdentifier(identifier); err != nil {
		return principaldomain.Principal{}, err
	}
	if actor == "" {
		return principaldomain.Principal{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return principaldomain.Principal{}, ErrNotFound
	}
	if _, claimed := s.identifiers[identifierKey(tenantID, identifier.Namespace, identifier.Value)]; claimed {
		return principaldomain.Principal{}, ErrIdentifierConflict
	}

	id, err := principaldomain.NewID()
	if err != nil {
		return principaldomain.Principal{}, err
	}
	created := principaldomain.Principal{
		ID:         id,
		TenantID:   tenantID,
		Kind:       kind,
		Status:     principaldomain.StatusActive,
		Identifier: identifier,
	}
	event, err := s.ledger.Append(ctx, principaldomain.EventCreated, tenantID, actor, principaldomain.CreatedPayload{
		PrincipalID:         id,
		TenantID:            tenantID,
		Kind:                kind,
		Status:              principaldomain.StatusActive,
		IdentifierNamespace: identifier.Namespace,
		IdentifierValue:     identifier.Value,
	})
	if err != nil {
		return principaldomain.Principal{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPrincipalCreated(event); err != nil {
		return principaldomain.Principal{}, err
	}
	s.writeSnapshotLocked(ctx, id)
	return created, nil
}

// PrincipalSuspend durably records a suspension. Suspending an already
// suspended principal is idempotent and appends no second event.
func (s *Service) PrincipalSuspend(
	ctx context.Context,
	principalID string,
	actor string,
) (principaldomain.Principal, error) {
	if err := s.requireLedger(); err != nil {
		return principaldomain.Principal{}, err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return principaldomain.Principal{}, err
	}
	if actor == "" {
		return principaldomain.Principal{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.principals[principalID]
	if !exists {
		return principaldomain.Principal{}, ErrPrincipalNotFound
	}
	if current.Status == principaldomain.StatusSuspended {
		return current, nil
	}

	event, err := s.ledger.Append(ctx, principaldomain.EventSuspended, current.TenantID, actor, principaldomain.SuspendedPayload{
		PrincipalID: principalID,
		TenantID:    current.TenantID,
	})
	if err != nil {
		return principaldomain.Principal{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPrincipalSuspended(event); err != nil {
		return principaldomain.Principal{}, err
	}
	s.writeSnapshotLocked(ctx, principalID)
	return s.principals[principalID], nil
}

// PrincipalGetByID returns one principal by public identifier.
func (s *Service) PrincipalGetByID(principalID string) (principaldomain.Principal, error) {
	if err := principaldomain.ValidateID(principalID); err != nil {
		return principaldomain.Principal{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found, exists := s.principals[principalID]
	if !exists {
		return principaldomain.Principal{}, ErrPrincipalNotFound
	}
	return found, nil
}

// PrincipalGetByIdentifier resolves a normalized identifier inside one tenant
// and namespace.
func (s *Service) PrincipalGetByIdentifier(
	tenantID string,
	identifier principaldomain.Identifier,
) (principaldomain.Principal, error) {
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return principaldomain.Principal{}, err
	}
	identifier.Value = principaldomain.NormalizeIdentifier(identifier.Value)
	if err := principaldomain.ValidateIdentifier(identifier); err != nil {
		return principaldomain.Principal{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, exists := s.identifiers[identifierKey(tenantID, identifier.Namespace, identifier.Value)]
	if !exists {
		return principaldomain.Principal{}, ErrPrincipalNotFound
	}
	return s.principals[id], nil
}

// writeSnapshotLocked checkpoints after a durable command; failure is logged,
// never fatal, because the event is already authoritative.
func (s *Service) writeSnapshotLocked(ctx context.Context, subject string) {
	if s.snapshots == nil {
		return
	}
	if err := s.snapshots.WriteSnapshot(ctx, s.exportStateLocked()); err != nil {
		s.logger.Warn("snapshot write failed after command",
			"subject", subject,
			"error", err.Error(),
		)
	}
}

func (s *Service) applyPrincipalCreated(event audit.Event) error {
	var payload principaldomain.CreatedPayload
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := s.admitPrincipal(principaldomain.Principal{
		ID:       payload.PrincipalID,
		TenantID: payload.TenantID,
		Kind:     payload.Kind,
		Status:   payload.Status,
		Identifier: principaldomain.Identifier{
			Namespace: payload.IdentifierNamespace,
			Value:     payload.IdentifierValue,
		},
	}); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	return nil
}

func (s *Service) applyPrincipalSuspended(event audit.Event) error {
	var payload principaldomain.SuspendedPayload
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	current, exists := s.principals[payload.PrincipalID]
	if !exists || current.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d suspends an unknown principal", event.Sequence)
	}
	current.Status = principaldomain.StatusSuspended
	s.principals[payload.PrincipalID] = current
	return nil
}

func (s *Service) admitPrincipal(created principaldomain.Principal) error {
	if err := principaldomain.ValidateID(created.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateID(created.TenantID); err != nil {
		return err
	}
	if err := principaldomain.ValidateKind(created.Kind); err != nil {
		return err
	}
	if created.Status != principaldomain.StatusActive && created.Status != principaldomain.StatusSuspended {
		return fmt.Errorf("principal status %q is not valid", created.Status)
	}
	if err := principaldomain.ValidateIdentifier(created.Identifier); err != nil {
		return err
	}
	if _, exists := s.byID[created.TenantID]; !exists {
		return fmt.Errorf("principal %s belongs to unknown tenant", created.ID)
	}
	if _, exists := s.principals[created.ID]; exists {
		return errors.New("duplicate principal ID")
	}
	claim := identifierKey(created.TenantID, created.Identifier.Namespace, created.Identifier.Value)
	if _, exists := s.identifiers[claim]; exists {
		return fmt.Errorf("identifier %s/%s is claimed twice", created.Identifier.Namespace, created.Identifier.Value)
	}
	s.principals[created.ID] = created
	s.identifiers[claim] = created.ID
	return nil
}

func (s *Service) admit(created tenantdomain.Tenant) error {
	if err := tenantdomain.ValidateID(created.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateName(created.Name); err != nil {
		return err
	}
	if _, exists := s.byName[created.Name]; exists {
		return fmt.Errorf("duplicate tenant name %q", created.Name)
	}
	if _, exists := s.byID[created.ID]; exists {
		return errors.New("duplicate tenant ID")
	}
	s.byName[created.Name] = created
	s.byID[created.ID] = created
	return nil
}
