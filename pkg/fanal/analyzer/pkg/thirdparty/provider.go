// Package thirdparty identifies the third-party OS package repository a package
// was distributed from, by provider name, from signals the OS package databases
// already expose.
package thirdparty

import (
	"slices"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ProviderPGDG is the PostgreSQL Global Development Group's own apt/yum
// repositories (apt.postgresql.org, download.postgresql.org).
const ProviderPGDG = "pgdg"

// RepositoryFromDebPackage classifies which repository a dpkg package was
// distributed from, composing every signal the package carries.
//
// A named provider outranks the maintainer heuristic: it is the higher-confidence
// signal, and only it can be resolved to a product to match advisories against.
func RepositoryFromDebPackage(pkg types.Package) types.PackageRepository {
	if provider := providerFromDebPackage(pkg); provider != "" {
		return types.PackageRepository{
			Class:   types.RepositoryClassThirdParty,
			Name:    provider,
			Product: product(pkg),
		}
	}
	if maintainerIsThirdParty(pkg.Maintainer) {
		return types.PackageRepository{
			Class: types.RepositoryClassThirdParty,
		}
	}
	return types.PackageRepository{
		Class: types.RepositoryClassOfficial,
	}
}

// providerFromDebPackage returns the provider name for a dpkg package, or an
// empty string when it carries no known provider marker. Both functions here
// take the whole package so a provider can be identified by composing however
// many of its fields it takes, even though each currently needs only one.
//
// PGDG's dpkg Maintainer field is byte-identical to official Debian's PostgreSQL
// team, so the revision is the only field that discriminates for dpkg. A plain
// substring match is deliberate: the suite number PGDG embeds varies
// ("1.pgdg13+2" on trixie, "1.pgdg120+1" on bookworm, "1.pgdg24.04+1" on Ubuntu
// noble) and backport revisions append further suffixes, while no official
// Debian or Ubuntu revision contains this string at all.
func providerFromDebPackage(pkg types.Package) string {
	if strings.Contains(pkg.SrcRelease, "pgdg") {
		return ProviderPGDG
	}
	return ""
}

// RepositoryFromRPMPackage classifies which repository an RPM package was
// distributed from, composing every signal the package carries.
//
// Note the inverted default against dpkg: RPM is classified third-party unless
// its vendor is one of the distros' own, so `Class` alone is a much weaker signal
// here than on dpkg. Only a non-empty `Name` means a provider was identified.
func RepositoryFromRPMPackage(pkg types.Package) types.PackageRepository {
	if vendorIsOfficial(pkg) {
		return types.PackageRepository{
			Class: types.RepositoryClassOfficial,
		}
	}
	if provider := providerFromRPMPackage(pkg); provider != "" {
		return types.PackageRepository{
			Class:   types.RepositoryClassThirdParty,
			Name:    provider,
			Product: product(pkg),
		}
	}
	return types.PackageRepository{
		Class: types.RepositoryClassThirdParty,
	}
}

// rpmVendors maps third-party RPM Vendor field values to provider names.
var rpmVendors = map[string]string{
	"PostgreSQL Global Development Group": ProviderPGDG,
}

// providerFromRPMPackage returns the provider name for an RPM package, or an
// empty string when it carries no known provider marker.
//
// Unlike dpkg, RPM has a dedicated Vendor field that discriminates on its own —
// the rpm analyzer surfaces it as Maintainer. PGDG's release tag ("1PGDG.rhel9.8")
// is a usable secondary signal if the Vendor field ever proves unreliable.
func providerFromRPMPackage(pkg types.Package) string {
	return rpmVendors[pkg.Maintainer]
}

// product returns the upstream product name for an OS package, by stripping the
// major-version marker that third-party repositories append to package names so
// several majors can be installed side by side: "postgresql-18" (dpkg) and
// "postgresql18" (rpm) both give "postgresql".
//
// CPE-derived advisory data is keyed on upstream product identity rather than on
// a repository's packaging name, so this is the name to look advisories up by.
//
// The strip is anchored to the package's own major version, not to any trailing
// digits: a name only loses a suffix that the version says is a major-version
// marker. That keeps names whose real spelling merely ends in a digit intact
// ("pgaudit-1.6", whose major is 1, not 6). It is still a heuristic — a product
// genuinely named after its own major ("psycopg2", major 2) is over-stripped,
// which costs a lookup miss rather than a wrong match.
func product(pkg types.Package) string {
	major, _, _ := strings.Cut(pkg.SrcVersion, ".")
	if major == "" {
		return pkg.SrcName
	}

	stripped := strings.TrimSuffix(pkg.SrcName, major)
	if stripped == pkg.SrcName {
		return pkg.SrcName
	}
	if stripped = strings.TrimSuffix(stripped, "-"); stripped == "" {
		return pkg.SrcName
	}
	return stripped
}

// Moved verbatim from the dpkg analyzer (upstream trivy #9917) so all repository
// classification lives in one place.
var (
	// thirdPartyMaintainerPatterns contains patterns that indicate a package is from a third-party repository.
	// Packages with maintainers matching these patterns will NOT have their InstalledFiles tracked,
	// allowing language scanners to properly analyze files installed by those packages.
	// See https://github.com/aquasecurity/trivy/issues/9916 for more details.
	thirdPartyMaintainerPatterns = []string{
		// Container & orchestration
		"support@docker.com", // Docker

		// Cloud providers & infrastructure
		"@nvidia.com",              // NVIDIA CUDA
		"Google Cloud CLI Authors", // Google Cloud SDK
		"sapmachine@sap.com",       // SAP Machine JDK
		"@hashicorp.com",           // HashiCorp (Terraform, Vault, Consul, etc.)
		"@microsoft.com",           // Microsoft (VS Code, Azure CLI, .NET, etc.)

		// Databases
		"@mongodb.com",                 // MongoDB
		"developers@lists.mariadb.org", // MariaDB
		"dev@couchdb.apache.org",       // Apache CouchDB
		"info@elastic.co",              // Elastic (Elasticsearch, Kibana, etc.)

		// Web servers & API gateways
		"nginx-packaging@f5.com", // NGINX (from nginx.org, not Debian)
		"@konghq.com",            // Kong
		"@cloudflare.com",        // Cloudflare (cloudflared, WARP)

		// Monitoring & observability
		"support@influxdb.com", // InfluxData (InfluxDB, Telegraf)
		"support@gitlab.com",   // GitLab
		"contact@grafana.com",  // Grafana Labs
		"@datadoghq.com",       // Datadog

		// Language runtimes (third-party repos)
		"@nodesource.com", // NodeSource (Node.js)

		// Networking & VPN
		"info@tailscale.com", // Tailscale

		// Robotics
		"@openrobotics.org",  // ROS (Robot Operating System)
		"@osrfoundation.org", // ROS (Robot Operating System)
	}

	// thirdPartyMaintainerExact contains maintainer strings that require exact match.
	// These are too short or generic for substring matching.
	thirdPartyMaintainerExact = []string{
		"GitHub",    // GitHub CLI
		"HashiCorp", // HashiCorp (Terraform, Vault, Consul, etc.)
	}
)

// maintainerIsThirdParty checks if a package is from a third-party repository
// by examining the Maintainer field against known third-party patterns.
//
// Unlike RPM which has a dedicated "Vendor" field, dpkg packages don't have a reliable
// way to identify their origin. We use a heuristic approach based on maintainer patterns.
// See https://github.com/aquasecurity/trivy/issues/9916 for more details.
func maintainerIsThirdParty(maintainer string) bool {
	if slices.Contains(thirdPartyMaintainerExact, maintainer) {
		return true
	}
	return slices.ContainsFunc(thirdPartyMaintainerPatterns, func(pattern string) bool {
		return strings.Contains(maintainer, pattern)
	})
}

// Moved verbatim from the rpm analyzer so all repository classification lives in
// one place. Note the inverted sense against the dpkg list above: this names the
// distros' own vendors, so anything absent from it is treated as third-party.
var osVendors = []string{
	"Amazon Linux",          // Amazon Linux 1
	"Amazon.com",            // Amazon Linux 2
	"CentOS",                // CentOS
	"Fedora Project",        // Fedora
	"Oracle America",        // Oracle Linux
	"Red Hat",               // Red Hat
	"AlmaLinux",             // AlmaLinux
	"CloudLinux",            // AlmaLinux
	"VMware",                // Photon OS
	"SUSE",                  // SUSE Linux Enterprise
	"openSUSE",              // openSUSE
	"Microsoft Corporation", // CBL-Mariner
	"Rocky",                 // Rocky Linux
}

// vendorIsOfficial reports whether the package came from its distro's own
// repository. The rpm analyzer surfaces the RPM Vendor field as Maintainer.
func vendorIsOfficial(pkg types.Package) bool {
	if pkg.Maintainer == "" {
		// Official Amazon packages may not contain `Vendor` field:
		// https://github.com/aquasecurity/trivy/issues/5887
		return strings.Contains(pkg.Release, "amzn")
	}

	for _, vendor := range osVendors {
		if strings.HasPrefix(pkg.Maintainer, vendor) {
			return true
		}
	}

	return false
}
