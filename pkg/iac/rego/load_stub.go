package rego

import (
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/set"
)

var builtinNamespaces = set.New("builtin", "defsec", "appshield")

func BuiltinNamespaces() []string {
	return builtinNamespaces.Items()
}

func IsBuiltinNamespace(namespace string) bool {
	return lo.ContainsBy(BuiltinNamespaces(), func(ns string) bool {
		return strings.HasPrefix(namespace, ns+".")
	})
}
