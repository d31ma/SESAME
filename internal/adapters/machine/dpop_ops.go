package machine

import (
	"context"
	"errors"

	"github.com/d31ma/sesame/internal/application/identity"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

// Stable DPoP wire codes.
//
// RFC 9449 gives a resource server one OAuth error to return — `invalid_token`
// — for every way a proof can fail, which is right at the HTTP boundary and
// useless in a log. These are finer so an operator can tell a client whose
// clock has drifted from one whose proof was lifted from another request, and
// a host maps whichever it gets onto the single wire error the RFC allows.
const (
	// ErrorDPoPProofInvalid covers everything structural: not a JWS, the wrong
	// `typ`, an unsupported algorithm, an unusable key, a bad signature.
	ErrorDPoPProofInvalid = "dpop_proof_invalid"
	// ErrorDPoPProofNotBound reports a proof whose method, URI, or `ath` does
	// not match the request it arrived with.
	ErrorDPoPProofNotBound = "dpop_proof_not_bound"
	// ErrorDPoPProofExpired reports a proof outside its one-minute window.
	ErrorDPoPProofExpired = "dpop_proof_expired"
	// ErrorDPoPProofReplayed reports a proof identifier presented twice. It is
	// the one DPoP failure that means something is wrong rather than that
	// something is broken.
	ErrorDPoPProofReplayed = "dpop_proof_replayed"
	// ErrorDPoPKeyMismatch reports a proof signed by a key other than the one
	// the token is bound to.
	ErrorDPoPKeyMismatch = "dpop_key_mismatch"
	// ErrorDPoPForeignOrigin reports a proof for a URI outside this
	// deployment's issuer origin.
	ErrorDPoPForeignOrigin = "dpop_foreign_origin"
	// ErrorDPoPRequired reports a key-bound token presented without a proof.
	ErrorDPoPRequired = "dpop_required"
)

// dpopRoutes are the operations this slice adds.
func (p *Processor) dpopRoutes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"oidc.dpop_verify": p.handleDPoPVerify,
	}
}

// handleDPoPVerify is the resource-server half of RFC 9449.
//
// The `http_method` and `http_uri` parameters are the host's assertion about
// the request it served, because the engine speaks no HTTP and cannot observe
// them. A host that reports them wrongly defeats the binding — which is why
// they are named rather than inferred, and why the engine separately refuses
// any URI outside its own issuer origin.
func (p *Processor) handleDPoPVerify(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"DPoP operations require a configured FYLO root")
	}
	var parameters struct {
		AccessToken string `json:"access_token"`
		Proof       string `json:"dpop_proof"`
		Method      string `json:"http_method"`
		URI         string `json:"http_uri"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	verification, err := p.tenant.DPoPVerify(ctx, parameters.AccessToken, parameters.Proof,
		parameters.Method, parameters.URI, "operator:machine")
	if err != nil {
		return dpopErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, verification)
}

// dpopErrorMap is the stable mapping from a DPoP failure to a wire code.
var dpopErrorMap = []struct {
	sentinel error
	code     string
	message  string
}{
	{oidcdomain.ErrDPoPProofMalformed, ErrorDPoPProofInvalid,
		"the DPoP proof is malformed"},
	{oidcdomain.ErrDPoPProofNotBound, ErrorDPoPProofNotBound,
		"the DPoP proof is not bound to this request"},
	{oidcdomain.ErrDPoPProofExpired, ErrorDPoPProofExpired,
		"the DPoP proof is outside its validity window"},
	{oidcdomain.ErrDPoPKeyMismatch, ErrorDPoPKeyMismatch,
		"the DPoP proof key does not match the token binding"},
	{identity.ErrDPoPProofReplayed, ErrorDPoPProofReplayed,
		"this DPoP proof has already been used"},
	{identity.ErrDPoPProofForeignOrigin, ErrorDPoPForeignOrigin,
		"the DPoP proof names a URI outside this issuer"},
	{identity.ErrDPoPRequired, ErrorDPoPRequired,
		"this token is key-bound and requires a DPoP proof"},
}

func dpopErrorResponse(requestID string, err error) Response {
	for _, mapping := range dpopErrorMap {
		if errors.Is(err, mapping.sentinel) {
			return errorResponse(requestID, mapping.code, mapping.message)
		}
	}
	return deviceErrorResponse(requestID, err)
}
