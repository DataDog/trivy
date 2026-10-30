package yarn

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func Test_yarnLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:           "90@1.0.0",
								Name:         "90",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								Licenses: []string{
									"MIT",
								},
								DependsOn: []string{
									"js-tokens@2.0.0",
									"prop-types@15.7.2",
									"scheduler@0.13.6",
								},
							},
							{
								ID:           "js-tokens@2.0.0",
								Name:         "js-tokens",
								Version:      "2.0.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:           "prop-types@15.7.2",
								Name:         "prop-types",
								Version:      "15.7.2",
								Dev:          true,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 27,
										EndLine:   34,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:           "scheduler@0.13.6",
								Name:         "scheduler",
								Version:      "0.13.6",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   47,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
								},
							},
							{
								ID:           "js-tokens@4.0.0",
								Name:         "js-tokens",
								Version:      "4.0.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:           "loose-envify@1.4.0",
								Name:         "loose-envify",
								Version:      "1.4.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"js-tokens@4.0.0",
								},
							},
							{
								ID:           "object-assign@4.1.1",
								Name:         "object-assign",
								Version:      "4.1.1",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   25,
									},
								},
							},
							{
								ID:           "react-is@16.13.1",
								Name:         "react-is",
								Version:      "16.13.1",
								Dev:          true,
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 36,
										EndLine:   39,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "project with workspace placed in sub dir",
			dir:  "testdata/project-with-workspace-in-subdir",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "foo/yarn.lock",
						Packages: types.Packages{
							{
								ID:           "@test/foo@1.0.0",
								Name:         "@test/foo",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								Licenses: []string{
									"MIT",
								},
								DependsOn: []string{
									"@test/bar-generators@0.0.1",
								},
							},
							{
								ID:           "@test/bar-generators@0.0.1",
								Name:         "@test/bar-generators",
								Version:      "0.0.1",
								Relationship: types.RelationshipWorkspace,
								DependsOn: []string{
									"hoek@6.1.3",
								},
							},
							{
								ID:           "hoek@6.1.3",
								Name:         "hoek",
								Version:      "6.1.3",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no package.json",
			dir:  "testdata/no-packagejson",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
							{
								ID:      "js-tokens@4.0.0",
								Name:    "js-tokens",
								Version: "4.0.0",
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   13,
									},
								},
							},
							{
								ID:      "loose-envify@1.4.0",
								Name:    "loose-envify",
								Version: "1.4.0",
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"js-tokens@4.0.0",
								},
							},
							{
								ID:      "object-assign@4.1.1",
								Name:    "object-assign",
								Version: "4.1.1",
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   25,
									},
								},
							},
							{
								ID:      "prop-types@15.7.2",
								Name:    "prop-types",
								Version: "15.7.2",
								Locations: []types.Location{
									{
										StartLine: 27,
										EndLine:   34,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:      "react-is@16.13.1",
								Name:    "react-is",
								Version: "16.13.1",
								Locations: []types.Location{
									{
										StartLine: 36,
										EndLine:   39,
									},
								},
							},
							{
								ID:      "scheduler@0.13.6",
								Name:    "scheduler",
								Version: "0.13.6",
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   47,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "wrong package.json",
			dir:  "testdata/wrong-packagejson",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:      "js-tokens@2.0.0",
								Name:    "js-tokens",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "unsupported_protocol",
			dir:  "testdata/unsupported_protocol",
			want: &analyzer.AnalysisResult{},
		},
		// docker run --rm -it node@sha256:2d5e8a8a51bc341fd5f2eed6d91455c3a3d147e91a14298fc564b5dc519c1666 sh
		// mkdir test && cd "$_"
		// yarn set version 3.4.1
		// yarn add is-callable@1.2.7 is-odd@3.0.1
		// yarn unplug is-callable@1.2.7
		// rm .yarn/cache/is-callable-npm*
		{
			name: "parse licenses (yarn v2+)",
			dir:  "testdata/yarn-licenses",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: []types.Package{
							{
								ID:           "yarn-3-licenses@1.0.0",
								Name:         "yarn-3-licenses",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"is-callable@1.2.7",
									"is-odd@3.0.1",
								},
							},
							{
								ID:           "is-callable@1.2.7",
								Name:         "is-callable",
								Version:      "1.2.7",
								Relationship: types.RelationshipDirect,
								Licenses:     []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 8,
										EndLine:   13,
									},
								},
							},
							{
								ID:           "is-odd@3.0.1",
								Name:         "is-odd",
								Version:      "3.0.1",
								Licenses:     []string{"MIT"},
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{"is-number@6.0.0"},
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   29,
									},
								},
							},
							{
								ID:           "is-number@6.0.0",
								Name:         "is-number",
								Version:      "6.0.0",
								Licenses:     []string{"MIT"},
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 15,
										EndLine:   20,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "package uses `latest` version",
			dir:  "testdata/latest-version",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:           "package.json",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"debug@4.3.5",
									"js-tokens@9.0.0",
								},
							},
							{
								ID:           "debug@4.3.5",
								Name:         "debug",
								Version:      "4.3.5",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
								DependsOn: []string{
									"ms@2.1.2",
								},
							},
							{
								ID:           "js-tokens@9.0.0",
								Name:         "js-tokens",
								Version:      "9.0.0",
								Relationship: types.RelationshipDirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 12,
										EndLine:   15,
									},
								},
							},
							{
								ID:           "ms@2.1.2",
								Name:         "ms",
								Version:      "2.1.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 17,
										EndLine:   20,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with alias rewrite",
			dir:  "testdata/alias",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:           "test@1.0.0",
								Name:         "test",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								Licenses: []string{
									"MIT",
								},
								DependsOn: []string{
									"foo-debug@4.3.4",
									"foo-json@0.8.33",
									"foo-ms@2.1.3",
									"foo-uuid@9.0.7",
								},
							},
							{
								ID:           "foo-json@0.8.33",
								Name:         "@types/jsonstream",
								Version:      "0.8.33",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 19,
										EndLine:   24,
									},
								},
								DependsOn: []string{
									"@types/node@20.10.5",
								},
							},
							{
								ID:           "foo-uuid@9.0.7",
								Name:         "@types/uuid",
								Version:      "9.0.7",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 31,
										EndLine:   34,
									},
								},
							},
							{
								ID:           "foo-debug@4.3.4",
								Name:         "debug",
								Version:      "4.3.4",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 12,
										EndLine:   17,
									},
								},
								DependsOn: []string{
									"ms@2.1.2",
								},
							},
							{
								ID:           "foo-ms@2.1.3",
								Name:         "ms",
								Version:      "2.1.3",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 26,
										EndLine:   29,
									},
								},
							},
							{
								ID:           "@types/node@20.10.5",
								Name:         "@types/node",
								Version:      "20.10.5",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
								DependsOn: []string{
									"undici-types@5.26.5",
								},
							},
							{
								ID:           "ms@2.1.2",
								Name:         "ms",
								Version:      "2.1.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 36,
										EndLine:   39,
									},
								},
							},
							{
								ID:           "undici-types@5.26.5",
								Name:         "undici-types",
								Version:      "5.26.5",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 41,
										EndLine:   44,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "monorepo",
			dir:  "testdata/monorepo",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:           "yarn-workspace-test@1.0.0",
								Name:         "yarn-workspace-test",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"c@0.0.0",
									"package1@0.0.0",
									"packages/package2/package.json",
									"prettier@2.8.8",
									"util1@0.0.0",
								},
							},
							{
								ID:           "packages/package2/package.json",
								Relationship: types.RelationshipWorkspace,
								DependsOn: []string{
									"is-odd@3.0.1",
								},
							},
							{
								ID:           "c@0.0.0",
								Name:         "c",
								Version:      "0.0.0",
								Relationship: types.RelationshipWorkspace,
								DependsOn: []string{
									"is-number@7.0.0",
								},
							},
							{
								ID:           "package1@0.0.0",
								Name:         "package1",
								Version:      "0.0.0",
								Relationship: types.RelationshipWorkspace,
								DependsOn: []string{
									"scheduler@0.23.0",
								},
							},
							{
								ID:           "util1@0.0.0",
								Name:         "util1",
								Version:      "0.0.0",
								Relationship: types.RelationshipWorkspace,
								DependsOn: []string{
									"js-tokens@8.0.1",
									"prop-types@15.8.1",
								},
							},
							{
								ID:           "is-number@7.0.0",
								Name:         "is-number",
								Version:      "7.0.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 23,
										EndLine:   28,
									},
								},
							},
							{
								ID:           "is-odd@3.0.1",
								Name:         "is-odd",
								Version:      "3.0.1",
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{"is-number@6.0.0"},
								Locations: []types.Location{
									{
										StartLine: 30,
										EndLine:   37,
									},
								},
							},
							{
								ID:           "js-tokens@8.0.1",
								Name:         "js-tokens",
								Version:      "8.0.1",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 46,
										EndLine:   51,
									},
								},
							},
							{
								ID:           "prettier@2.8.8",
								Name:         "prettier",
								Version:      "2.8.8",
								Relationship: types.RelationshipDirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 87,
										EndLine:   94,
									},
								},
							},
							{
								ID:           "prop-types@15.8.1",
								Name:         "prop-types",
								Version:      "15.8.1",
								Relationship: types.RelationshipDirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 96,
										EndLine:   105,
									},
								},
								DependsOn: []string{
									"loose-envify@1.4.0",
									"object-assign@4.1.1",
									"react-is@16.13.1",
								},
							},
							{
								ID:           "scheduler@0.23.0",
								Name:         "scheduler",
								Version:      "0.23.0",
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{"loose-envify@1.4.0"},
								Locations: []types.Location{
									{
										StartLine: 114,
										EndLine:   121,
									},
								},
							},
							{
								ID:           "is-number@6.0.0",
								Name:         "is-number",
								Version:      "6.0.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 16,
										EndLine:   21,
									},
								},
							},
							{
								ID:           "js-tokens@4.0.0",
								Name:         "js-tokens",
								Version:      "4.0.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 39,
										EndLine:   44,
									},
								},
							},
							{
								ID:           "loose-envify@1.4.0",
								Name:         "loose-envify",
								Version:      "1.4.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								DependsOn:    []string{"js-tokens@4.0.0"},
								Locations: []types.Location{
									{
										StartLine: 53,
										EndLine:   62,
									},
								},
							},
							{
								ID:           "object-assign@4.1.1",
								Name:         "object-assign",
								Version:      "4.1.1",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 64,
										EndLine:   69,
									},
								},
							},
							{
								ID:           "react-is@16.13.1",
								Name:         "react-is",
								Version:      "16.13.1",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
								Locations: []types.Location{
									{
										StartLine: 107,
										EndLine:   112,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "workspace with node_modules",
			dir:  "testdata/workspace-node-modules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: types.Packages{
							{
								ID:           "yarn-workspace-test@1.0.0",
								Name:         "yarn-workspace-test",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"a@0.0.0",
								},
							},
							{
								ID:           "a@0.0.0",
								Name:         "a",
								Version:      "0.0.0",
								Relationship: types.RelationshipWorkspace,
								DependsOn: []string{
									"is-odd@3.0.1",
								},
							},
							{
								ID:           "is-odd@3.0.1",
								Name:         "is-odd",
								Version:      "3.0.1",
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{"is-number@6.0.0"},
								Licenses:     []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 23,
										EndLine:   30,
									},
								},
							},
							{
								ID:           "is-number@6.0.0",
								Name:         "is-number",
								Version:      "6.0.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Licenses:     []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 16,
										EndLine:   21,
									},
								},
							},
						},
					},
				},
			},
		},
		// docker run --rm -it node@sha256:2d5e8a8a51bc341fd5f2eed6d91455c3a3d147e91a14298fc564b5dc519c1666 sh
		// mkdir test && cd "$_"
		// yarn set version 1.22.19
		// yarn add @vue/compiler-sfc@2.7.14
		{
			name: "parse licenses (yarn classic)",
			dir:  "testdata/yarn-classic-licenses",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Yarn,
						FilePath: "yarn.lock",
						Packages: []types.Package{
							{
								ID:           "package.json",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"@vue/compiler-sfc@2.7.14",
								},
							},
							{
								ID:           "@vue/compiler-sfc@2.7.14",
								Name:         "@vue/compiler-sfc",
								Version:      "2.7.14",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   17,
									},
								},
								DependsOn: []string{
									"@babel/parser@7.22.7",
									"postcss@8.4.27",
									"source-map@0.6.1",
								},
							},
							{
								ID:           "@babel/parser@7.22.7",
								Name:         "@babel/parser",
								Version:      "7.22.7",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   8,
									},
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:           "nanoid@3.3.6",
								Name:         "nanoid",
								Version:      "3.3.6",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 19,
										EndLine:   22,
									},
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:           "picocolors@1.0.0",
								Name:         "picocolors",
								Version:      "1.0.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 24,
										EndLine:   27,
									},
								},
								Licenses: []string{"ISC"},
							},
							{
								ID:           "postcss@8.4.27",
								Name:         "postcss",
								Version:      "8.4.27",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 29,
										EndLine:   36,
									},
								},
								Licenses: []string{"MIT"},
								DependsOn: []string{
									"nanoid@3.3.6",
									"picocolors@1.0.0",
									"source-map-js@1.0.2",
								},
							},
							{
								ID:           "source-map@0.6.1",
								Name:         "source-map",
								Version:      "0.6.1",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 43,
										EndLine:   46,
									},
								},
								Licenses: []string{"BSD-3-Clause"},
							},
							{
								ID:           "source-map-js@1.0.2",
								Name:         "source-map-js",
								Version:      "1.0.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 38,
										EndLine:   41,
									},
								},
								Licenses: []string{"BSD-3-Clause"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yarnLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path yarn.lock",
			filePath: "test/yarn.lock",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "test/package-lock.json",
			want:     false,
		},
		{
			name:     "yarn cache",
			filePath: ".yarn/cache/websocket-driver-npm-0.7.4-a72739da70-fffe5a33fe.zip",
			want:     true,
		},
		{
			name:     "not a yarn cache",
			filePath: "cache/is-number-npm-6.0.0-30881e83e6-f73bfced03.zip",
			want:     false,
		},
		{
			name:     "yarn.lock in node_modules",
			filePath: "somedir/node_modules/uri-js/yarn.lock",
			want:     false,
		},
		{
			name:     "yarn.lock in unplugged",
			filePath: "somedir/.yarn/unplugged/uri-js/yarn.lock",
			want:     false,
		},
		{
			name:     "deep package.json",
			filePath: "somedir/node_modules/canvg/node_modules/parse5/package.json",
			want:     true,
		},
		{
			name:     "license file",
			filePath: "node_modules/@vue/compiler-sfc/LICENSE",
			want:     false,
		},
		{
			name:     "txt license file",
			filePath: "node_modules/@vue/compiler-sfc/LICENSE.txt",
			want:     false,
		},
		{
			name:     "lowercase license file",
			filePath: "node_modules/picocolors/license",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := yarnAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

// isOddLock is a yarn.lock that holds is-odd.
const isOddLock = `# yarn lockfile v1

is-odd@^3.0.1:
  version "3.0.1"
`

// packageIDs returns the sorted IDs of the packages of the single
// application in r.
func packageIDs(t *testing.T, r *analyzer.AnalysisResult) []string {
	t.Helper()
	require.Len(t, r.Applications, 1)
	var ids []string
	for _, pkg := range r.Applications[0].Packages {
		ids = append(ids, pkg.ID)
	}
	slices.Sort(ids)
	return ids
}

func Test_yarnLibraryAnalyzer_PostAnalyze_workspaceAboveRoot(t *testing.T) {
	// The scanned files are linked from layer, as CreateLink links them,
	// and the workspace pattern climbs to a package.json beside layer.
	tmp := t.TempDir()
	files := map[string]string{
		"layer/app/yarn.lock":      isOddLock,
		"layer/app/package.json":   `{"name": "root", "version": "1.0.0", "dependencies": {"is-odd": "^3.0.1"}, "workspaces": ["../../host/*"]}`,
		"host/secret/package.json": `{"name": "secret", "version": "6.6.6"}`,
	}
	for name, data := range files {
		p := filepath.Join(tmp, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
	layer := filepath.Join(tmp, "layer")
	fsys := mapfs.New(mapfs.WithUnderlyingRoot(layer))
	require.NoError(t, fsys.MkdirAll("app", os.ModePerm))
	for _, name := range []string{"app/yarn.lock", "app/package.json"} {
		require.NoError(t, fsys.WriteFile(name, filepath.Join(layer, filepath.FromSlash(name))))
	}

	a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)
	got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{FS: fsys})
	require.NoError(t, err)
	assert.Equal(t, []string{"is-odd@3.0.1", "root@1.0.0"}, packageIDs(t, got))
}

func Test_yarnLibraryAnalyzer_PostAnalyze_workspacesBesideNodeModules(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		files   []string // the package.json of each workspace and of left-pad
	}{
		{
			// * matches api, node_modules and web, in that order.
			name:    "one level",
			pattern: "*",
			files:   []string{"api", "node_modules/left-pad", "web"},
		},
		{
			name:    "any depth",
			pattern: "packages/**",
			files:   []string{"packages/api", "packages/web", "packages/web/node_modules/left-pad"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"yarn.lock":    {Data: []byte(isOddLock)},
				"package.json": {Data: []byte(`{"name": "root", "version": "1.0.0", "workspaces": ["` + tt.pattern + `"]}`)},
			}
			for _, dir := range tt.files {
				data := fmt.Sprintf(`{"name": %q, "version": "1.0.0", "dependencies": {"is-odd": "^3.0.1"}}`, path.Base(dir))
				fsys[dir+"/package.json"] = &fstest.MapFile{Data: []byte(data)}
			}

			a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)
			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{FS: fsys})
			require.NoError(t, err)
			assert.Equal(t, []string{"api@1.0.0", "is-odd@3.0.1", "root@1.0.0", "web@1.0.0"}, packageIDs(t, got))
		})
	}
}

func Test_yarnLibraryAnalyzer_PostAnalyze_patternCharsInDir(t *testing.T) {
	for _, dir := range []string{"{{cookiecutter.slug}}", "x{y", "a*b", "a?b", "[ab]", `a\b`} {
		t.Run(dir, func(t *testing.T) {
			fsys := fstest.MapFS{
				dir + "/yarn.lock":               {Data: []byte(isOddLock)},
				dir + "/package.json":            {Data: []byte(`{"name": "root", "version": "1.0.0", "workspaces": ["packages/*"]}`)},
				dir + "/packages/a/package.json": {Data: []byte(`{"name": "a", "version": "1.0.0", "dependencies": {"is-odd": "^3.0.1"}}`)},
			}

			a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)
			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{FS: fsys})
			require.NoError(t, err)
			assert.Equal(t, []string{"a@1.0.0", "is-odd@3.0.1", "root@1.0.0"}, packageIDs(t, got))
		})
	}
}

// cancelFS calls cancel when the file name is opened.
type cancelFS struct {
	fs.FS
	name   string
	cancel context.CancelFunc
}

func (c cancelFS) Open(name string) (fs.File, error) {
	if name == c.name {
		c.cancel()
	}
	return c.FS.Open(name)
}

func Test_yarnLibraryAnalyzer_PostAnalyze_canceled(t *testing.T) {
	// The context ends while yarn reads the package.json beside yarn.lock,
	// before it finds the workspaces and the dev dependencies.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fsys := cancelFS{
		FS: fstest.MapFS{
			"yarn.lock":               {Data: []byte(isOddLock)},
			"package.json":            {Data: []byte(`{"name": "root", "version": "1.0.0", "devDependencies": {"is-odd": "^3.0.1"}, "workspaces": ["packages/*"]}`)},
			"packages/a/package.json": {Data: []byte(`{"name": "a", "version": "1.0.0"}`)},
		},
		name:   "package.json",
		cancel: cancel,
	}

	a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)
	got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{FS: fsys})
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, got.Applications)
}

// Benchmark_yarnLibraryAnalyzer_PostAnalyze analyzes monorepos whose
// yarn.lock holds libraries of 4 leaves each. Each workspace depends on
// 5 libraries and has a dev dependency on another. The files are in a
// mapfs, as in a scan.
func Benchmark_yarnLibraryAnalyzer_PostAnalyze(b *testing.B) {
	const (
		leaves = 4 // per library
		deps   = 5 // per workspace
	)
	for _, size := range []struct {
		workspaces int
		libs       int
	}{
		{workspaces: 100, libs: 1000},
		{workspaces: 1000, libs: 2000},
	} {
		name := fmt.Sprintf("workspaces=%d/packages=%d", size.workspaces, size.libs*(1+leaves))
		b.Run(name, func(b *testing.B) {
			var lock strings.Builder
			lock.WriteString("# yarn lockfile v1\n")
			for i := range size.libs {
				fmt.Fprintf(&lock, "\nlib-%d@^1.0.0:\n  version \"1.0.0\"\n  dependencies:\n", i)
				for j := range leaves {
					fmt.Fprintf(&lock, "    leaf-%d \"^1.0.0\"\n", leaves*i+j)
				}
			}
			for i := range leaves * size.libs {
				fmt.Fprintf(&lock, "\nleaf-%d@^1.0.0:\n  version \"1.0.0\"\n", i)
			}

			fsys := mapfs.New()
			write := func(name string, data []byte) {
				require.NoError(b, fsys.MkdirAll(path.Dir(name), os.ModePerm))
				require.NoError(b, fsys.WriteVirtualFile(name, data, 0o644))
			}
			write("yarn.lock", []byte(lock.String()))
			write("package.json", []byte(`{"name": "root", "version": "1.0.0", "workspaces": ["packages/*"]}`))
			for w := range size.workspaces {
				prod := make(map[string]string)
				for j := range deps {
					prod[fmt.Sprintf("lib-%d", (deps*w+j)%size.libs)] = "^1.0.0"
				}
				dev := map[string]string{fmt.Sprintf("lib-%d", (deps*w+size.libs/2)%size.libs): "^1.0.0"}
				data, err := json.Marshal(map[string]any{
					"name":            fmt.Sprintf("ws-%d", w),
					"version":         "1.0.0",
					"dependencies":    prod,
					"devDependencies": dev,
				})
				require.NoError(b, err)
				write(fmt.Sprintf("packages/ws-%d/package.json", w), data)
			}

			a, err := newYarnAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(b, err)
			got, err := a.PostAnalyze(b.Context(), analyzer.PostAnalysisInput{FS: fsys})
			require.NoError(b, err)
			require.Len(b, got.Applications[0].Packages, 1+size.workspaces+size.libs*(1+leaves))

			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.PostAnalyze(b.Context(), analyzer.PostAnalysisInput{FS: fsys}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
