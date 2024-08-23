package rego

import (
	"strings"

	"github.com/samber/lo"
)

var builtinNamespaces = map[string]struct{}{
	"builtin":   {},
	"defsec":    {},
	"appshield": {},
}

func BuiltinNamespaces() []string {
	return lo.Keys(builtinNamespaces)
}

func IsBuiltinNamespace(namespace string) bool {
	return lo.ContainsBy(BuiltinNamespaces(), func(ns string) bool {
		return strings.HasPrefix(namespace, ns+".")
	})
}
