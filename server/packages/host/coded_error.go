// Package host holds the errors SESAME's Yon host raises around the engine.
// They live outside server/errors so the identity provider can use them.
package host

// CodedError is an error with a stable, public code that is safe to answer.
type CodedError interface {
	error
	ErrorCode() string
}
