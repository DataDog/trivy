package dpkg

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_dpkgFileFilterHook_Hook(t *testing.T) {
	tests := []struct {
		name   string
		result *analyzer.AnalysisResult
		want   *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			result: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: os.Debian,
				},
				SystemInstalledFiles: map[string][]string{
					"python2.7": {
						"/",
						"/usr/bin/pydoc",
						"/usr/bin/python",
						"/usr/bin/python2",
						"/usr/bin/python2.7",
						"/usr/libexec/platform-python",
						"/usr/share/doc/python-2.7.5",
						"/usr/share/doc/python-2.7.5/LICENSE",
						"/usr/share/doc/python-2.7.5/README",
						"/usr/share/man/man1/python.1.gz",
						"/usr/share/man/man1/python2.1.gz",
						"/usr/share/man/man1/python2.7.1.gz",
						"/usr/lib64/python2.7/distutils/command/install_egg_info.py",
						"/usr/lib64/python2.7/distutils/command/install_egg_info.pyc",
						"/usr/lib64/python2.7/distutils/command/install_egg_info.pyo",
						"/usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
						"usr/lib64/python2.7/wsgiref.egg-info", // without the leading slash
					},
				},
				PackageInfos: []types.PackageInfo{
					{
						Packages: types.Packages{
							types.Package{
								Name: "python2.7",
							},
						},
					},
				},
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: os.Debian,
				},
				SystemInstalledFiles: map[string][]string{
					"python2.7": {
						"/",
						"/usr/bin/pydoc",
						"/usr/bin/python",
						"/usr/bin/python2",
						"/usr/bin/python2.7",
						"/usr/libexec/platform-python",
						"/usr/share/doc/python-2.7.5",
						"/usr/share/doc/python-2.7.5/LICENSE",
						"/usr/share/doc/python-2.7.5/README",
						"/usr/share/man/man1/python.1.gz",
						"/usr/share/man/man1/python2.1.gz",
						"/usr/share/man/man1/python2.7.1.gz",
						"/usr/lib64/python2.7/distutils/command/install_egg_info.py",
						"/usr/lib64/python2.7/distutils/command/install_egg_info.pyc",
						"/usr/lib64/python2.7/distutils/command/install_egg_info.pyo",
						"/usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
						"usr/lib64/python2.7/wsgiref.egg-info", // without the leading slash
					},
				},
				PackageInfos: []types.PackageInfo{
					{
						Packages: types.Packages{
							types.Package{
								Name: "python2.7",
								SystemInstalledFiles: []string{
									"/",
									"/usr/bin/pydoc",
									"/usr/bin/python",
									"/usr/bin/python2",
									"/usr/bin/python2.7",
									"/usr/libexec/platform-python",
									"/usr/share/doc/python-2.7.5",
									"/usr/share/doc/python-2.7.5/LICENSE",
									"/usr/share/doc/python-2.7.5/README",
									"/usr/share/man/man1/python.1.gz",
									"/usr/share/man/man1/python2.1.gz",
									"/usr/share/man/man1/python2.7.1.gz",
									"/usr/lib64/python2.7/distutils/command/install_egg_info.py",
									"/usr/lib64/python2.7/distutils/command/install_egg_info.pyc",
									"/usr/lib64/python2.7/distutils/command/install_egg_info.pyo",
									"/usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
									"usr/lib64/python2.7/wsgiref.egg-info", // without the leading slash

								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := newDpkgHandler(artifact.Option{KeepSystemInstalledFiles: true})
			require.NoError(t, err)
			err = h.Handle(context.TODO(), tt.result, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.result, tt.want)
		})
	}
}
