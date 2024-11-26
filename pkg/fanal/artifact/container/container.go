// Should stay in sync with github.com/aquasecurity/trivy/pkg/fanal/artifact/image/image.go.

package local

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/containerd/continuity/devices"
	"github.com/docker/docker/pkg/system"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	imageutils "github.com/aquasecurity/trivy/pkg/fanal/image/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	"github.com/aquasecurity/trivy/pkg/semaphore"
)

var (
	ArtifactSet = wire.NewSet(
		walker.NewFS,
		wire.Bind(new(Walker), new(*walker.FS)),
		NewArtifact,
	)
	_ Walker = (*walker.FS)(nil)
)

type Walker interface {
	Walk(root string, opt walker.Option, fn walker.WalkFunc) error
}

type Artifact struct {
	logger         *log.Logger
	container      types.Container
	cache          cache.ArtifactCache
	walker         Walker
	analyzer       analyzer.AnalyzerGroup
	configAnalyzer analyzer.ConfigAnalyzerGroup // analyzer for container image config
	handlerManager handler.Manager
	walkerOption   walker.Option

	artifactOption artifact.Option
}

type LayerInfo struct {
	DiffID    string
	Path      string
	CreatedBy string // can be empty
}

func NewArtifact(ctr types.Container, c cache.ArtifactCache, w Walker, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler init error: %w", err)
	}

	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	artifact := Artifact{
		logger:         log.WithPrefix("container"),
		container:      ctr,
		cache:          c,
		walker:         w,
		analyzer:       a,
		handlerManager: handlerManager,
		artifactOption: opt,
		// keep a copy of walker options to mutate it and not
		// make these changes part of the cache key calculations.
		walkerOption: opt.WalkerOption,
	}

	// Root SkipFiles, SkipDirs and OnlyDirs list of files to each layer path.
	artifact.walkerOption.SkipFiles = rootFiles(ctr.Layers(), artifact.walkerOption.SkipFiles)
	artifact.walkerOption.SkipDirs = rootFiles(ctr.Layers(), artifact.walkerOption.SkipDirs)
	artifact.walkerOption.OnlyDirs = rootFiles(ctr.Layers(), artifact.walkerOption.OnlyDirs)

	// Don't skip non-regular files.
	artifact.walkerOption.AllFiles = true

	return artifact, nil
}

func (a Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	imageID, err := a.container.ID()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}
	a.logger.Debug("Detected image ID", log.String("image_id", imageID))

	configFile, err := a.container.ConfigFile()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	diffIDs := a.diffIDs(configFile)
	a.logger.Debug("Detected diff ID", log.Any("diff_ids", diffIDs))

	// Try to detect base layers.
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	a.logger.Debug("Detected base layers", log.Any("diff_ids", baseDiffIDs))

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return artifact.Reference{}, err
	}

	// Parse histories and extract a list of "created_by"
	layerKeyMap := a.consolidateCreatedBy(diffIDs, layerKeys, configFile)

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		a.logger.Debug("Missing image ID in cache", log.String("image_id", imageID))
	} else {
		missingImageKey = ""
	}

	if err = a.inspect(ctx, missingImageKey, missingLayers, baseDiffIDs, layerKeyMap, configFile); err != nil {
		return artifact.Reference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return artifact.Reference{
		Name:    a.container.Name(),
		Type:    artifact.TypeContainerImage,
		ID:      imageKey,
		BlobIDs: layerKeys,
		ImageMetadata: artifact.ImageMetadata{
			ID:          imageID,
			DiffIDs:     diffIDs,
			RepoTags:    a.container.RepoTags(),
			RepoDigests: a.container.RepoDigests(),
			ConfigFile:  *configFile,
		},
	}, nil
}

func (Artifact) Clean(_ artifact.Reference) error {
	return nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.analyzer.AnalyzerVersions(), nil, artifact.Option{})
	if err != nil {
		return "", nil, err
	}

	hookVersions := a.handlerManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), hookVersions, a.artifactOption)
		if err != nil {
			return "", nil, err
		}
		layerKeys = append(layerKeys, blobKey)
	}
	return imageKey, layerKeys, nil
}

func (a Artifact) consolidateCreatedBy(diffIDs, layerKeys []string, configFile *v1.ConfigFile) map[string]LayerInfo {
	// save createdBy fields in order of layers
	var createdBy []string
	for _, h := range configFile.History {
		// skip histories for empty layers
		if h.EmptyLayer {
			continue
		}
		c := strings.TrimPrefix(h.CreatedBy, "/bin/sh -c ")
		c = strings.TrimPrefix(c, "#(nop) ")
		createdBy = append(createdBy, c)
	}

	// If history detected incorrect - use only diffID
	// TODO: our current logic may not detect empty layers correctly in rare cases.
	validCreatedBy := len(diffIDs) == len(createdBy)

	layerKeyMap := make(map[string]LayerInfo)
	for i, diffID := range diffIDs {
		c := ""
		if validCreatedBy {
			c = createdBy[i]
		}

		layerKey := layerKeys[i]
		path := ""
		for _, layer := range a.container.Layers() {
			if diffID == layer.DiffID {
				path = layer.Path
			}
		}
		layerKeyMap[layerKey] = LayerInfo{
			Path:      path,
			DiffID:    diffID,
			CreatedBy: c,
		}
	}
	return layerKeyMap
}

func (a Artifact) inspect(ctx context.Context, missingImage string, layerKeys, baseDiffIDs []string,
	layerKeyMap map[string]LayerInfo, configFile *v1.ConfigFile) error {

	var osFound types.OS
	p := parallel.NewPipeline(a.artifactOption.Parallel, false, layerKeys, func(ctx context.Context,
		layerKey string) (any, error) {
		layer := layerKeyMap[layerKey]

		// If it is a base layer, secret scanning should not be performed.
		var disabledAnalyzers []analyzer.Type
		if slices.Contains(baseDiffIDs, layer.DiffID) {
			disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeSecret)
		}

		layerInfo, err := a.inspectLayer(ctx, layer, disabledAnalyzers)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze layer (%s): %w", layer.DiffID, err)
		}
		if err = a.cache.PutBlob(layerKey, layerInfo); err != nil {
			return nil, xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
		}
		if lo.IsNotEmpty(layerInfo.OS) {
			osFound = layerInfo.OS
		}
		return nil, nil

	}, nil)

	if err := p.Do(ctx); err != nil {
		return xerrors.Errorf("pipeline error: %w", err)
	}

	if missingImage != "" {
		if err := a.inspectConfig(ctx, missingImage, osFound, configFile); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil
}

func (a Artifact) inspectLayer(ctx context.Context, layerInfo LayerInfo, disabled []analyzer.Type) (types.BlobInfo, error) {
	a.logger.Debug("Missing diff ID in cache", log.String("diff_id", layerInfo.DiffID))

	layerDigest, err := a.uncompressedLayer(layerInfo.DiffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", layerInfo.DiffID, err)
	}

	// Prepare variables
	var wg sync.WaitGroup
	opts := analyzer.AnalysisOptions{
		Offline:         a.artifactOption.Offline,
		FileChecksum:    a.artifactOption.FileChecksum,
		WalkErrCallback: a.artifactOption.GetWalkerErrorCallback(),
	}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Parallel)

	// Prepare filesystem for post analysis
	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	whFiles := make([]string, 0)
	opqDirs := make([]string, 0)

	err = a.walker.Walk(layerInfo.Path, a.walkerOption, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		dir := layerInfo.Path

		// When the directory is the same as the filePath, a file was given
		// instead of a directory, rewrite the file path and directory in this case.
		if filePath == "." {
			dir, filePath = path.Split(layerInfo.Path)
		}

		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			// Skip symbolic links, since they may point to files located in another layer.
			return nil
		}

		if info.Mode()&os.ModeCharDevice != 0 {
			maj, min, err := devices.DeviceInfo(info)
			if err != nil {
				return xerrors.Errorf("DeviceInfo: %w", err)
			}
			if maj == 0 && min == 0 {
				whFiles = append(whFiles, filePath)
				return nil
			}
		}

		if info.Mode()&os.ModeDir != 0 {
			xattrs := []string{
				"user.overlay.opaque",
				"trusted.overlay.opaque",
			}
			for _, xattr := range xattrs {
				opaque, err := system.Lgetxattr(filePath, xattr)
				if err != nil {
					return xerrors.Errorf("Lgetattr: %w", err)
				}
				if len(opaque) == 1 && opaque[0] == 'y' {
					opqDirs = append(opqDirs, filePath)
					return nil
				}
			}
		}

		if err := a.analyzer.AnalyzeFile(ctx, &wg, limit, result, dir, filePath, info, opener, nil, opts); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}

		// Skip post analysis if the file is not required
		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		// Build filesystem for post analysis
		if err := composite.CreateLink(analyzerTypes, dir, filePath, filepath.Join(dir, filePath)); err != nil {
			return xerrors.Errorf("failed to create link: %w", err)
		}

		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Post-analysis
	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post analysis error: %w", err)
	}

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		Digest:            layerDigest,
		DiffID:            layerInfo.DiffID,
		CreatedBy:         layerInfo.CreatedBy,
		OpaqueDirs:        opqDirs,
		WhiteoutFiles:     whFiles,
		OS:                result.OS,
		Repository:        result.Repository,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: result.Misconfigurations,
		Secrets:           result.Secrets,
		Licenses:          result.Licenses,
		CustomResources:   result.CustomResources,
	}

	// Call post handlers to modify blob info
	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post handler error: %w", err)
	}

	return blobInfo, nil
}

func (a Artifact) diffIDs(configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}
	return lo.Map(configFile.RootFS.DiffIDs, func(diffID v1.Hash, _ int) string {
		return diffID.String()
	})
}

func (a Artifact) uncompressedLayer(diffID string) (string, error) {
	layer, err := a.container.LayerByDiffID(diffID)
	if err != nil {
		return "", err
	}
	return layer.Digest, nil
}

func (a Artifact) inspectConfig(ctx context.Context, imageID string, osFound types.OS, config *v1.ConfigFile) error {
	result := lo.FromPtr(a.configAnalyzer.AnalyzeImageConfig(ctx, osFound, config))

	info := types.ArtifactInfo{
		SchemaVersion:    types.ArtifactJSONSchemaVersion,
		Architecture:     config.Architecture,
		Created:          config.Created.Time,
		DockerVersion:    config.DockerVersion,
		OS:               config.OS,
		Misconfiguration: result.Misconfiguration,
		Secret:           result.Secret,
		HistoryPackages:  result.HistoryPackages,
	}

	if err := a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}

// guessBaseLayers guesses layers in base image (call base layers).
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	baseImageIndex := imageutils.GuessBaseImageIndex(configFile.History)
	if baseImageIndex < 0 {
		baseImageIndex = 0
	}

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range configFile.History {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}

func rootFiles(layers []types.LayerPath, files []string) []string {
	s := make([]string, 0)
	for _, layer := range layers {
		for _, file := range files {
			s = append(s, filepath.Join(layer.Path, file))
		}
	}
	return s
}
