package server

import (
	"polyglot/api/internal/problem"
)

// Re-export problem constants, types, and helpers for callers of the server package.
const (
	ContentTypeProblemJSON = problem.ContentTypeProblemJSON

	CodeInvalidRequest    = problem.CodeInvalidRequest
	CodeUnauthorized      = problem.CodeUnauthorized
	CodeUnknownWallet     = problem.CodeUnknownWallet
	CodeRequestExpired    = problem.CodeRequestExpired
	CodeReplayed          = problem.CodeReplayed
	CodeSignerRejected    = problem.CodeSignerRejected
	CodeSignerUnavailable = problem.CodeSignerUnavailable
)

// ProblemDetails aliases the core RFC 9457 problem details struct.
type ProblemDetails = problem.ProblemDetails

var (
	NewProblem           = problem.New
	WriteProblem         = problem.Write
	WriteProblemDetails  = problem.WriteDetails
	ErrUnauthorized      = problem.ErrUnauthorized
	ErrForbidden         = problem.ErrForbidden
	ErrInvalidRequest    = problem.ErrInvalidRequest
	ErrUnknownWallet     = problem.ErrUnknownWallet
	ErrRequestExpired    = problem.ErrRequestExpired
	ErrReplayed          = problem.ErrReplayed
	ErrSignerRejected    = problem.ErrSignerRejected
	ErrSignerUnavailable = problem.ErrSignerUnavailable
)
