// Should stay in sync with github.com/aquasecurity/trivy/pkg/fanal/artifact/image/image.go.
//
// A MultiLayer artifact is an ordered set of pre-extracted filesystem
// layers. The shape is identical to a multi-layer container image, so the
// analysis pipeline mirrors image.go - only the layer ingestion differs
// (filesystem walk instead of tar stream walk; no compressed blobs, no
// image config file). Use cases include serverless function packaging
// (e.g. AWS Lambda function code + layer ZIPs), pre-extracted OCI images,
// and any other "scan N filesystem trees as overlay layers" flow.
package multilayer

import (
	"context"
	"os"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	"github.com/aquasecurity/trivy/pkg/semaphore"
)

const artifactVersion = 1

type Artifact struct {
	logger         *log.Logger
	source         types.MultiLayer
	cache          cache.ArtifactCache
	walker         *walker.FS
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

func NewArtifact(src types.MultiLayer, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler init error: %w", err)
	}

	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	return Artifact{
		logger:         log.WithPrefix("multilayer"),
		source:         src,
		cache:          c,
		walker:         walker.NewFS(),
		analyzer:       a,
		handlerManager: handlerManager,

		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (ref artifact.Reference, err error) {
	artifactID, err := a.source.ID()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the artifact ID: %w", err)
	}
	a.logger.Debug("Detected artifact ID", log.String("artifact_id", artifactID))

	layers := a.source.Layers()
	if len(layers) == 0 {
		return artifact.Reference{}, xerrors.New("multilayer artifact has no layers")
	}

	diffIDs := make([]string, len(layers))
	for i, l := range layers {
		if l.DiffID == "" {
			return artifact.Reference{}, xerrors.Errorf("multilayer layer %d (%s) has no DiffID", i, l.Path)
		}
		diffIDs[i] = l.DiffID
	}
	a.logger.Debug("Detected diff IDs", log.Any("diff_ids", diffIDs))

	artifactKey, layerKeys, err := a.calcCacheKeys(artifactID, diffIDs)
	if err != nil {
		return artifact.Reference{}, err
	}

	layerKeyMap := make(map[string]types.LayerSource, len(layers))
	for i, l := range layers {
		layerKeyMap[layerKeys[i]] = l
	}

	missingArtifact, missingLayers, err := a.cache.MissingBlobs(ctx, artifactKey, layerKeys)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	if !missingArtifact {
		a.logger.Debug("Artifact metadata cached", log.String("artifact_id", artifactID))
	}

	if err = a.inspect(ctx, missingLayers, layerKeyMap); err != nil {
		return artifact.Reference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return artifact.Reference{
		Name:    a.source.Name(),
		Type:    types.TypeMultiLayer,
		ID:      artifactKey,
		BlobIDs: layerKeys,
		ImageMetadata: artifact.ImageMetadata{
			ID:      artifactID,
			DiffIDs: diffIDs,
		},
	}, nil
}

func (a Artifact) Clean(_ artifact.Reference) error {
	return nil
}

func (a Artifact) calcCacheKeys(artifactID string, diffIDs []string) (string, []string, error) {
	artifactKey, err := cache.CalcKey(artifactID, artifactVersion, analyzer.Versions{}, nil, artifact.Option{})
	if err != nil {
		return "", nil, err
	}

	hookVersions := a.handlerManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, artifactVersion, a.analyzer.AnalyzerVersions(), hookVersions, a.artifactOption)
		if err != nil {
			return "", nil, err
		}
		layerKeys = append(layerKeys, blobKey)
	}
	return artifactKey, layerKeys, nil
}

func (a Artifact) inspect(ctx context.Context, layerKeys []string, layerKeyMap map[string]types.LayerSource) error {
	var osFound types.OS
	p := parallel.NewPipeline(a.artifactOption.Parallel, false, layerKeys, func(ctx context.Context,
		layerKey string) (any, error) {
		layer := layerKeyMap[layerKey]

		layerInfo, err := a.inspectLayer(ctx, layer)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze layer (%s): %w", layer.DiffID, err)
		}
		if err = a.cache.PutBlob(ctx, layerKey, layerInfo); err != nil {
			return nil, xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
		}
		return layerInfo.OS, nil

	}, func(res any) error {
		osInfo := res.(types.OS)
		osFound.Merge(osInfo)
		return nil
	})

	if err := p.Do(ctx); err != nil {
		return xerrors.Errorf("pipeline error: %w", err)
	}
	return nil
}

func (a Artifact) inspectLayer(ctx context.Context, layer types.LayerSource) (types.BlobInfo, error) {
	a.logger.Debug("Analyzing layer", log.String("diff_id", layer.DiffID), log.String("path", layer.Path))

	eg, egCtx := errgroup.WithContext(ctx)

	opts := analyzer.AnalysisOptions{
		Offline:             a.artifactOption.Offline,
		OfflineJar:          a.artifactOption.OfflineJar,
		FileChecksum:        a.artifactOption.FileChecksum,
		FileChecksumJar:     a.artifactOption.FileChecksumJar,
		WalkErrCallback:     a.artifactOption.GetWalkerErrorCallback(),
		PostAnalyzerTimeout: a.artifactOption.PostAnalyzerTimeout,
	}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Parallel)

	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	walkerOption := a.artifactOption.WalkerOption
	walkerOption.AllFiles = true
	err = a.walker.Walk(ctx, layer.Path, walkerOption, func(ctx context.Context, filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err := a.analyzer.AnalyzeFile(egCtx, eg, limit, result, layer.Path, filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}

		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return xerrors.Errorf("failed to copy file to temp: %w", err)
		}
		if err := composite.CreateLink(analyzerTypes, "", filePath, tmpFilePath); err != nil {
			return xerrors.Errorf("failed to write a file: %w", err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	if err = eg.Wait(); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("analyze error: %w", err)
	}

	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post analysis error: %w", err)
	}

	result.Sort()

	digest := layer.Digest
	if digest == "" {
		digest = layer.DiffID
	}
	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		Digest:            digest,
		DiffID:            layer.DiffID,
		CreatedBy:         layer.CreatedBy,
		Annotations:       layer.Annotations,
		OS:                result.OS,
		Repository:        result.Repository,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: result.Misconfigurations,
		Secrets:           result.Secrets,
		Licenses:          result.Licenses,
		CustomResources:   result.CustomResources,
		BuildInfo:         result.BuildInfo,
	}

	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post handler error: %w", err)
	}

	return blobInfo, nil
}
