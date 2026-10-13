package testutil

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func CreateFS(files map[string]string) fs.FS {
	return fstest.MapFS(lo.MapEntries(files, func(k, v string) (string, *fstest.MapFile) {
		return strings.TrimPrefix(k, "/"), &fstest.MapFile{Data: []byte(v)}
	}))
}

func AssertDefsecEqual(t *testing.T, expected, actual any) {
	expectedJson, err := json.MarshalIndent(expected, "", "\t")
	require.NoError(t, err)
	actualJson, err := json.MarshalIndent(actual, "", "\t")
	require.NoError(t, err)

	if expectedJson[0] == '[' {
		var expectedSlice []map[string]any
		require.NoError(t, json.Unmarshal(expectedJson, &expectedSlice))
		var actualSlice []map[string]any
		require.NoError(t, json.Unmarshal(actualJson, &actualSlice))
		expectedSlice = purgeMetadataSlice(expectedSlice)
		actualSlice = purgeMetadataSlice(actualSlice)
		assert.Equal(t, expectedSlice, actualSlice, "defsec adapted and expected values do not match")
	} else {
		var expectedMap map[string]any
		require.NoError(t, json.Unmarshal(expectedJson, &expectedMap))
		var actualMap map[string]any
		require.NoError(t, json.Unmarshal(actualJson, &actualMap))
		expectedMap = purgeMetadata(expectedMap)
		actualMap = purgeMetadata(actualMap)
		assert.Equal(t, expectedMap, actualMap, "defsec adapted and expected values do not match")
	}
}

func purgeMetadata(input map[string]any) map[string]any {
	for k, v := range input {
		if k == "metadata" || k == "Metadata" {
			delete(input, k)
			continue
		}
		if v, ok := v.(map[string]any); ok {
			input[k] = purgeMetadata(v)
		}
		if v, ok := v.([]any); ok {
			if len(v) > 0 {
				if _, ok := v[0].(map[string]any); ok {
					maps := make([]map[string]any, len(v))
					for i := range v {
						maps[i] = v[i].(map[string]any)
					}
					input[k] = purgeMetadataSlice(maps)
				}
			}
		}
	}
	return input
}

func purgeMetadataSlice(input []map[string]any) []map[string]any {
	for i := range input {
		input[i] = purgeMetadata(input[i])
	}
	return input
}
