package json_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

// See npm.LockFile
type nestedStruct struct {
	Dependencies map[string]Dependency `json:"dependencies"`
}

type Dependency struct {
	Version      string                `json:"version"`
	Dependencies map[string]Dependency `json:"dependencies"`
	xjson.Location
}

type stringWithLocation struct {
	Requires Requires `json:"requires"`
}

type Requires []Require

type Require struct {
	Dependency string
	xjson.Location
}

func (r *Require) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &r.Dependency)
}

func TestUnmarshal(t *testing.T) {
	t.Run("nested LocationObjects", func(t *testing.T) {
		in := []byte(`{
    "dependencies": {
        "body-parser": {
            "version": "1.18.3",
            "dependencies": {
                "debug": {
                    "version": "2.6.9"
                }
            }
        }
    }
}`)
		var out nestedStruct
		err := xjson.Unmarshal(in, &out)
		require.NoError(t, err)
		require.Equal(t, nestedStruct{
			Dependencies: map[string]Dependency{
				"body-parser": {
					Version: "1.18.3",
					Dependencies: map[string]Dependency{
						"debug": {
							Version: "2.6.9",
						},
					},
				},
			},
		}, out)
	})

	t.Run("Location for only string", func(t *testing.T) {
		in := []byte(`{
    "version": "0.5",
    "requires": [
        "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
        "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245"
    ]
}`)
		var out stringWithLocation
		err := xjson.Unmarshal(in, &out)
		require.NoError(t, err)
		require.Equal(t, stringWithLocation{
			Requires: []Require{
				{
					Dependency: "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
				},
				{
					Dependency: "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245",
				},
			},
		}, out)
	})
}
