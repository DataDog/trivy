package rego

// DefaultAllowedRegoErrors defines the default number of Rego compile errors
// that the scanner will tolerate. This value is set explicitly instead of
// relying on OPA's ast.CompileErrorLimitDefault to avoid depending on upstream changes.
const DefaultAllowedRegoErrors = 10

type Scanner struct {
}
