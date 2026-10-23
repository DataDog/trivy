package npm

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v1 && cd node_v1
	// npm init --force
	// npm install --save finalhandler@1.1.1 body-parser@1.18.3 ms@1.0.0 @babel/helper-string-parser@7.19.4
	// npm install --save-dev debug@2.5.2
	// npm install --save-optional promise
	// npm i --lockfile-version 1
	// packages are filled manually

	npmV1Pkgs = []ftypes.Package{
		{
			ID:           "@babel/helper-string-parser@7.19.4",
			Name:         "@babel/helper-string-parser",
			Version:      "7.19.4",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.19.4.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "asap@2.0.6",
			Name:         "asap",
			Version:      "2.0.6",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "body-parser@1.18.3",
			Name:         "body-parser",
			Version:      "1.18.3",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "bytes@3.0.0",
			Name:         "bytes",
			Version:      "3.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "content-type@1.0.5",
			Name:         "content-type",
			Version:      "1.0.5",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "debug@2.5.2",
			Name:         "debug",
			Version:      "2.5.2",
			Dev:          true,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.5.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "debug@2.6.9",
			Name:         "debug",
			Version:      "2.6.9",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []ftypes.Location{{}, {}},
		},
		{
			ID:           "depd@1.1.2",
			Name:         "depd",
			Version:      "1.1.2",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ee-first@1.1.1",
			Name:         "ee-first",
			Version:      "1.1.1",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "encodeurl@1.0.2",
			Name:         "encodeurl",
			Version:      "1.0.2",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "escape-html@1.0.3",
			Name:         "escape-html",
			Version:      "1.0.3",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "finalhandler@1.1.1",
			Name:         "finalhandler",
			Version:      "1.1.1",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "http-errors@1.6.3",
			Name:         "http-errors",
			Version:      "1.6.3",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "iconv-lite@0.4.23",
			Name:         "iconv-lite",
			Version:      "0.4.23",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "inherits@2.0.3",
			Name:         "inherits",
			Version:      "2.0.3",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "media-typer@0.3.0",
			Name:         "media-typer",
			Version:      "0.3.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "mime-db@1.52.0",
			Name:         "mime-db",
			Version:      "1.52.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "mime-types@2.1.35",
			Name:         "mime-types",
			Version:      "2.1.35",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@0.7.2",
			Name:         "ms",
			Version:      "0.7.2",
			Dev:          true,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-0.7.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@1.0.0",
			Name:         "ms",
			Version:      "1.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@2.0.0",
			Name:         "ms",
			Version:      "2.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}, {}},
		},
		{
			ID:           "on-finished@2.3.0",
			Name:         "on-finished",
			Version:      "2.3.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "parseurl@1.3.3",
			Name:         "parseurl",
			Version:      "1.3.3",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "promise@8.3.0",
			Name:         "promise",
			Version:      "8.3.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/promise/-/promise-8.3.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "qs@6.5.2",
			Name:         "qs",
			Version:      "6.5.2",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "raw-body@2.3.3",
			Name:         "raw-body",
			Version:      "2.3.3",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "safer-buffer@2.1.2",
			Name:         "safer-buffer",
			Version:      "2.1.2",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "setprototypeof@1.1.0",
			Name:         "setprototypeof",
			Version:      "1.1.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "statuses@1.4.0",
			Name:         "statuses",
			Version:      "1.4.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "type-is@1.6.18",
			Name:         "type-is",
			Version:      "1.6.18",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "unpipe@1.0.0",
			Name:         "unpipe",
			Version:      "1.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipUnknown,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
	}

	// dependencies are filled manually
	npmDeps = []ftypes.Dependency{
		{
			ID: "body-parser@1.18.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"content-type@1.0.5",
				"debug@2.6.9",
				"depd@1.1.2",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"on-finished@2.3.0",
				"qs@6.5.2",
				"raw-body@2.3.3",
				"type-is@1.6.18",
			},
		},
		{
			ID:        "debug@2.5.2",
			DependsOn: []string{"ms@0.7.2"},
		},
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID: "finalhandler@1.1.1",
			DependsOn: []string{
				"debug@2.6.9",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"statuses@1.4.0",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "http-errors@1.6.3",
			DependsOn: []string{
				"depd@1.1.2",
				"inherits@2.0.3",
				"setprototypeof@1.1.0",
				"statuses@1.4.0",
			},
		},
		{
			ID:        "iconv-lite@0.4.23",
			DependsOn: []string{"safer-buffer@2.1.2"},
		},
		{
			ID:        "mime-types@2.1.35",
			DependsOn: []string{"mime-db@1.52.0"},
		},
		{
			ID:        "on-finished@2.3.0",
			DependsOn: []string{"ee-first@1.1.1"},
		},
		{
			ID:        "promise@8.3.0",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID: "raw-body@2.3.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "type-is@1.6.18",
			DependsOn: []string{
				"media-typer@0.3.0",
				"mime-types@2.1.35",
			},
		},
	}

	// ... and
	// npm i --lockfile-version 2
	// same as npmV1Pkgs but change `Indirect` field to false for `body-parser@1.18.3`, `finalhandler@1.1.1`, `@babel/helper-string-parser@7.19.4`, `promise@8.3.0` and `ms@1.0.0`  packages.
	// also need to get locations from `packages` struct
	// --- lockfile version 3 ---
	// npm i --lockfile-version 3
	// same as npmV2Pkgs.
	npmV2Pkgs = []ftypes.Package{
		{
			ID:           "@babel/helper-string-parser@7.19.4",
			Name:         "@babel/helper-string-parser",
			Version:      "7.19.4",
			Dev:          false,
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.19.4.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "body-parser@1.18.3",
			Name:         "body-parser",
			Version:      "1.18.3",
			Dev:          false,
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "debug@2.5.2",
			Name:         "debug",
			Version:      "2.5.2",
			Dev:          true,
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.5.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "finalhandler@1.1.1",
			Name:         "finalhandler",
			Version:      "1.1.1",
			Dev:          false,
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@1.0.0",
			Name:         "ms",
			Version:      "1.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "promise@8.3.0",
			Name:         "promise",
			Version:      "8.3.0",
			Dev:          false,
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/promise/-/promise-8.3.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "asap@2.0.6",
			Name:         "asap",
			Version:      "2.0.6",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "bytes@3.0.0",
			Name:         "bytes",
			Version:      "3.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "content-type@1.0.5",
			Name:         "content-type",
			Version:      "1.0.5",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "debug@2.6.9",
			Name:         "debug",
			Version:      "2.6.9",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []ftypes.Location{{}, {}},
		},
		{
			ID:           "depd@1.1.2",
			Name:         "depd",
			Version:      "1.1.2",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ee-first@1.1.1",
			Name:         "ee-first",
			Version:      "1.1.1",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "encodeurl@1.0.2",
			Name:         "encodeurl",
			Version:      "1.0.2",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "escape-html@1.0.3",
			Name:         "escape-html",
			Version:      "1.0.3",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "http-errors@1.6.3",
			Name:         "http-errors",
			Version:      "1.6.3",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "iconv-lite@0.4.23",
			Name:         "iconv-lite",
			Version:      "0.4.23",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "inherits@2.0.3",
			Name:         "inherits",
			Version:      "2.0.3",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "media-typer@0.3.0",
			Name:         "media-typer",
			Version:      "0.3.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "mime-db@1.52.0",
			Name:         "mime-db",
			Version:      "1.52.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "mime-types@2.1.35",
			Name:         "mime-types",
			Version:      "2.1.35",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@0.7.2",
			Name:         "ms",
			Version:      "0.7.2",
			Dev:          true,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-0.7.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@2.0.0",
			Name:         "ms",
			Version:      "2.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}, {}},
		},
		{
			ID:           "on-finished@2.3.0",
			Name:         "on-finished",
			Version:      "2.3.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "parseurl@1.3.3",
			Name:         "parseurl",
			Version:      "1.3.3",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "qs@6.5.2",
			Name:         "qs",
			Version:      "6.5.2",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "raw-body@2.3.3",
			Name:         "raw-body",
			Version:      "2.3.3",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "safer-buffer@2.1.2",
			Name:         "safer-buffer",
			Version:      "2.1.2",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "setprototypeof@1.1.0",
			Name:         "setprototypeof",
			Version:      "1.1.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "statuses@1.4.0",
			Name:         "statuses",
			Version:      "1.4.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "type-is@1.6.18",
			Name:         "type-is",
			Version:      "1.6.18",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "unpipe@1.0.0",
			Name:         "unpipe",
			Version:      "1.0.0",
			Dev:          false,
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
	}

	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v3_with_workspace && cd node_v3_with_workspace
	// npm init --force
	// npm init -w ./functions/func1 !!! use `function1` name for package
	// grep -v "version" ./functions/func1/package.json > tmpfile && mv tmpfile ./functions/func1/package.json
	// npm init -w ./functions/nested_func --force
	// npm install --save debug@2.5.2
	// sed -i 's/\^/=/g' package.json
	// npm install --save debug@2.6.9 -w nested_func
	// npm install nested_func -w function1
	// grep -v "functions/func1" ./package.json > tmpfile && mv tmpfile ./package.json
	// sed -i 's/functions\/nested_func/functions\/*/g' package.json
	// npm update
	// packages are filled manually
	npmV3WithWorkspacePkgs = []ftypes.Package{
		{
			ID:           "debug@2.5.2",
			Name:         "debug",
			Version:      "2.5.2",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.5.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "function1",
			Name:         "function1",
			Version:      "",
			Licenses:     []string{"ISC"},
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "functions/func1",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "nested_func@1.0.0",
			Name:         "nested_func",
			Version:      "1.0.0",
			Licenses:     []string{"ISC"},
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "functions/nested_func",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "debug@2.6.9",
			Name:         "debug",
			Version:      "2.6.9",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@0.7.2",
			Name:         "ms",
			Version:      "0.7.2",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-0.7.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@2.0.0",
			Name:         "ms",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
	}

	npmV3WithWorkspaceDeps = []ftypes.Dependency{
		{
			ID:        "debug@2.5.2",
			DependsOn: []string{"ms@0.7.2"},
		},
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID:        "function1",
			DependsOn: []string{"nested_func@1.0.0"},
		},
		{
			ID:        "nested_func@1.0.0",
			DependsOn: []string{"debug@2.6.9"},
		},
	}

	npmV3WithWorkspaceAsObjectPkgs = []ftypes.Package{
		{
			ID:           "testapp@1.0.0",
			Name:         "testapp",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "testapp",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "lodash@4.17.21",
			Name:         "lodash",
			Version:      "4.17.21",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
	}
	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v3_with_peer && cd node_v3_with_peer
	// npm init --force
	// npm install --save winston-mail@2.0.0
	// npm install --save-peer lodash@4.17.21
	// npm update
	//
	// Delete unnecessary packages from package-lock.json
	// Packages are filled manually
	npmV3WithPeerDependenciesPkgs = []ftypes.Package{
		{
			ID:           "lodash@4.17.21",
			Name:         "lodash",
			Version:      "4.17.21",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "winston-mail@2.0.0",
			Name:         "winston-mail",
			Version:      "2.0.0",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/winston-mail/-/winston-mail-2.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "mustache@2.3.2",
			Name:         "mustache",
			Version:      "2.3.2",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/mustache/-/mustache-2.3.2.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "triple-beam@1.4.1",
			Name:         "triple-beam",
			Version:      "1.4.1",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/triple-beam/-/triple-beam-1.4.1.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "winston@3.17.0",
			Name:         "winston",
			Version:      "3.17.0",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/winston/-/winston-3.17.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
	}
	npmV3WithPeerDependenciesDeps = []ftypes.Dependency{
		{
			ID: "winston-mail@2.0.0",
			DependsOn: []string{
				"mustache@2.3.2",
				"winston@3.17.0",
			},
		},
		{
			ID:        "winston@3.17.0",
			DependsOn: []string{"triple-beam@1.4.1"},
		},
	}

	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v3_without_direct_deps && cd node_v3_without_direct_deps
	// npm init --force
	// npm init -w ./functions/func1 --force
	// npm install --save debug@2.6.9 -w func1
	// packages are filled manually
	npmV3WithoutRootDepsField = []ftypes.Package{
		{
			ID:           "func1@1.0.0",
			Name:         "func1",
			Version:      "1.0.0",
			Licenses:     []string{"ISC"},
			Relationship: ftypes.RelationshipDirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "functions/func1",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "debug@2.6.9",
			Name:         "debug",
			Version:      "2.6.9",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "ms@2.0.0",
			Name:         "ms",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
	}

	npmV3WithoutRootDepsFieldDeps = []ftypes.Dependency{
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID:        "func1@1.0.0",
			DependsOn: []string{"debug@2.6.9"},
		},
	}

	npmV3WithSameDevAndNonDevPkgs = []ftypes.Package{
		{
			ID:           "fsevents@1.2.9",
			Name:         "fsevents",
			Version:      "1.2.9",
			Relationship: ftypes.RelationshipDirect,
			Dev:          true,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/fsevents/-/fsevents-1.2.9.tgz",
				},
			},
			Locations: []ftypes.Location{{}},
		},
		{
			ID:           "minimist@0.0.8",
			Name:         "minimist",
			Version:      "0.0.8",
			Relationship: ftypes.RelationshipDirect,
			Dev:          false,
			ExternalReferences: []ftypes.ExternalRef{
				{
					Type: ftypes.RefOther,
					URL:  "https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz",
				},
			},
			Licenses:  []string{"MIT"},
			Locations: []ftypes.Location{{}, {}},
		},
		{
			ID:           "mkdirp@0.5.1",
			Name:         "mkdirp",
			Version:      "0.5.1",
			Licenses:     []string{"MIT"},
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Locations:    []ftypes.Location{{}},
		},
		{
			ID:           "node-pre-gyp@0.12.0",
			Name:         "node-pre-gyp",
			Version:      "0.12.0",
			Licenses:     []string{"BSD-3-Clause"},
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Locations:    []ftypes.Location{{}},
		},
	}

	npmV3WithSameDevAndNonDevDeps = []ftypes.Dependency{
		{
			ID:        "fsevents@1.2.9",
			DependsOn: []string{"node-pre-gyp@0.12.0"},
		},
		{
			ID:        "mkdirp@0.5.1",
			DependsOn: []string{"minimist@0.0.8"},
		},
		{
			ID:        "node-pre-gyp@0.12.0",
			DependsOn: []string{"mkdirp@0.5.1"},
		},
	}
)
