// Package host holds the errors SESAME's Yon host raises around the engine.
package host

// CodedError is an error with a stable, public code that is safe to answer.
type CodedError interface {
	error
	ErrorCode() string
}
