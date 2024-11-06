package licensing_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

func TestClassifier_FullClassify(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     *types.LicenseFile
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "C file with AGPL-3.0",
			filePath: "testdata/licensed.c",
			want: &types.LicenseFile{
				FilePath: "testdata/licensed.c",
			},
		},
		{
			name:     "Creative commons License file",
			filePath: "testdata/LICENSE_creativecommons",
			want: &types.LicenseFile{
				FilePath: "testdata/LICENSE_creativecommons",
			},
		},
		{
			name:     "Apache 2 License file",
			filePath: "testdata/LICENSE_apache2",
			want: &types.LicenseFile{
				FilePath: "testdata/LICENSE_apache2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contentFile, err := os.Open(tt.filePath)
			require.NoError(t, err)
			defer contentFile.Close()

			got, err := licensing.Classify(tt.filePath, contentFile, 0.9)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
