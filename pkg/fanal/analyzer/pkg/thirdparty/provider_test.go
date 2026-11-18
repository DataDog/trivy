package thirdparty

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_providerFromDebPackage(t *testing.T) {
	tests := []struct {
		name     string
		revision string
		want     string
	}{
		{
			name:     "PGDG on Debian trixie",
			revision: "1.pgdg13+2",
			want:     "pgdg",
		},
		{
			name:     "PGDG on Debian bookworm",
			revision: "1.pgdg120+1",
			want:     "pgdg",
		},
		{
			name:     "PGDG on Ubuntu noble",
			revision: "1.pgdg24.04+1",
			want:     "pgdg",
		},
		{
			name:     "PGDG backport revision with a trailing suffix",
			revision: "1.pgdg110+1~bpo11+1",
			want:     "pgdg",
		},
		{
			name:     "official Debian revision",
			revision: "1",
			want:     "",
		},
		{
			name:     "official Debian security revision",
			revision: "13+deb11u4",
			want:     "",
		},
		{
			name:     "official Ubuntu revision",
			revision: "0ubuntu0.22.04.1",
			want:     "",
		},
		{
			name:     "empty",
			revision: "",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, providerFromDebPackage(types.Package{
				Name:       "postgresql-18",
				SrcName:    "postgresql-18",
				SrcVersion: "18.6",
				SrcRelease: tt.revision,
			}))
		})
	}
}

func Test_providerFromRPMPackage(t *testing.T) {
	tests := []struct {
		name   string
		vendor string
		want   string
	}{
		{
			name:   "PGDG",
			vendor: "PostgreSQL Global Development Group",
			want:   "pgdg",
		},
		{
			name:   "official Rocky Linux",
			vendor: "Rocky Enterprise Software Foundation",
			want:   "",
		},
		{
			name:   "empty",
			vendor: "",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, providerFromRPMPackage(types.Package{
				Name:       "postgresql18-server",
				SrcName:    "postgresql18",
				Maintainer: tt.vendor,
			}))
		})
	}
}

func Test_product(t *testing.T) {
	tests := []struct {
		name    string
		srcName string
		srcVer  string
		want    string
	}{
		{
			name:    "dpkg name carrying its major",
			srcName: "postgresql-18",
			srcVer:  "18.6",
			want:    "postgresql",
		},
		{
			name:    "rpm name carrying its major",
			srcName: "postgresql18",
			srcVer:  "18.6",
			want:    "postgresql",
		},
		{
			name:    "name embedding major.minor keeps its spelling",
			srcName: "pgaudit-1.6",
			srcVer:  "1.6.3",
			want:    "pgaudit-1.6",
		},
		{
			name:    "trailing digit that is not the major is kept",
			srcName: "wal2json",
			srcVer:  "2.6",
			want:    "wal2json",
		},
		{
			name:    "no version marker",
			srcName: "pgbouncer",
			srcVer:  "1.24.1",
			want:    "pgbouncer",
		},
		{
			name:    "known limitation: name is its own major",
			srcName: "psycopg2",
			srcVer:  "2.9.10",
			want:    "psycopg",
		},
		{
			name:    "stripping everything keeps the original name",
			srcName: "389",
			srcVer:  "389.1",
			want:    "389",
		},
		{
			name:    "no source version",
			srcName: "postgresql-18",
			srcVer:  "",
			want:    "postgresql-18",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, product(types.Package{
				SrcName:    tt.srcName,
				SrcVersion: tt.srcVer,
			}))
		})
	}
}

func TestRepositoryFromDebPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  types.Package
		want types.PackageRepository
	}{
		{
			name: "provider identified by revision",
			pkg: types.Package{
				Name:       "postgresql-18",
				SrcName:    "postgresql-18",
				SrcVersion: "18.6",
				SrcRelease: "1.pgdg13+2",
				Maintainer: "Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>",
			},
			want: types.PackageRepository{
				Class:   types.RepositoryClassThirdParty,
				Name:    "pgdg",
				Product: "postgresql",
			},
		},
		{
			name: "third-party by maintainer, no provider to name",
			pkg: types.Package{
				Name:       "docker-ce",
				SrcName:    "docker-ce",
				SrcRelease: "1",
				Maintainer: "Docker <support@docker.com>",
			},
			want: types.PackageRepository{
				Class: types.RepositoryClassThirdParty,
			},
		},
		{
			name: "official Debian package",
			pkg: types.Package{
				Name:       "libc6",
				SrcName:    "glibc",
				SrcRelease: "12",
				Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
			},
			want: types.PackageRepository{
				Class: types.RepositoryClassOfficial,
			},
		},
		{
			name: "official package whose maintainer is a third-party org upstream lists exactly",
			pkg: types.Package{
				Name:       "gh",
				SrcName:    "gh",
				SrcRelease: "1",
				Maintainer: "GitHub",
			},
			want: types.PackageRepository{
				Class: types.RepositoryClassThirdParty,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RepositoryFromDebPackage(tt.pkg))
		})
	}
}

// Ported from the dpkg analyzer's Test_isThirdPartyPackage, which moved here with
// the maintainer heuristic. Exercised through the exported classifier.
func TestRepositoryFromDebPackage_MaintainerHeuristic(t *testing.T) {
	tests := []struct {
		name       string
		maintainer string
		want       types.RepositoryClass
	}{
		{"third-party (Docker)", "Docker <support@docker.com>", types.RepositoryClassThirdParty},
		{"third-party (GitHub - exact match)", "GitHub", types.RepositoryClassThirdParty},
		{"official (Ubuntu)", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", types.RepositoryClassOfficial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RepositoryFromDebPackage(types.Package{Maintainer: tt.maintainer})
			assert.Equal(t, tt.want, got.Class)
			assert.Empty(t, got.Name)
		})
	}
}

func TestRepositoryFromRPMPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  types.Package
		want types.PackageRepository
	}{
		{
			name: "PGDG provider identified by vendor",
			pkg: types.Package{
				Name:       "postgresql18-server",
				SrcName:    "postgresql18",
				SrcVersion: "18.6",
				Release:    "1PGDG.rhel9.8",
				Maintainer: "PostgreSQL Global Development Group",
			},
			want: types.PackageRepository{
				Class:   types.RepositoryClassThirdParty,
				Name:    "pgdg",
				Product: "postgresql",
			},
		},
		{
			name: "official Rocky package",
			pkg: types.Package{
				Name:       "postgresql",
				SrcName:    "postgresql",
				Maintainer: "Rocky Enterprise Software Foundation",
			},
			want: types.PackageRepository{
				Class: types.RepositoryClassOfficial,
			},
		},
		{
			name: "unknown vendor falls back to unnamed third-party",
			pkg: types.Package{
				Name:       "custom-build",
				SrcName:    "custom-build",
				Maintainer: "Some Internal Build Farm",
			},
			want: types.PackageRepository{
				Class: types.RepositoryClassThirdParty,
			},
		},
		{
			name: "empty vendor with amzn release is official",
			pkg: types.Package{
				Name:    "glibc",
				SrcName: "glibc",
				Release: "60.amzn2.0.1",
			},
			want: types.PackageRepository{
				Class: types.RepositoryClassOfficial,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RepositoryFromRPMPackage(tt.pkg))
		})
	}
}
