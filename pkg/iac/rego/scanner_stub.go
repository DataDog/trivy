package rego

// CompileErrorLimit defines the default compile error limit.
// We set this value explicitly instead of relying on OPA's ast.CompileErrorLimitDefault
// to avoid dependency on potential upstream changes.
const CompileErrorLimit = 10

type Scanner struct {
}
