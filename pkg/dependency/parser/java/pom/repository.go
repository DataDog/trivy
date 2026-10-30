package pom

import (
	"errors"
	"net/url"

	"github.com/aquasecurity/trivy/pkg/log"
)

// mavenCentralRepoID is the conventional <id> for the default Maven Central
// repository. <mirror> rules use it (e.g. <mirrorOf>central</mirrorOf>), so
// it must be the same wherever we construct a repository pointing at Central.
const mavenCentralRepoID = "central"

var centralURL, _ = url.Parse("https://repo.maven.apache.org/maven2/")

type repository struct {
	id              string // <id> from settings.xml/pom.xml; used for <mirror> matching
	url             url.URL
	releaseEnabled  bool
	snapshotEnabled bool
}

var mavenCentralRepo = repository{
	id:             mavenCentralRepoID,
	url:            *centralURL,
	releaseEnabled: true,
}

func resolvePomRepos(pomRepos []pomRepository) []repository {
	logger := log.WithPrefix("pom")
	var repos []repository
	for _, rep := range pomRepos {
		r := repository{
			id: rep.ID,
			// "<enabled>: true or false for whether this repository is enabled for the respective type (releases or snapshots). By default, this is true."
			// cf. https://maven.apache.org/pom.html#Repositories
			releaseEnabled:  rep.ReleasesEnabled == trueString || rep.ReleasesEnabled == "",
			snapshotEnabled: rep.SnapshotsEnabled == trueString || rep.SnapshotsEnabled == "",
		}

		// Add only enabled repositories
		if !r.releaseEnabled && !r.snapshotEnabled {
			continue
		}

		repoURL, err := url.Parse(rep.URL)
		if err != nil {
			if ue, ok := errors.AsType[*url.Error](err); ok {
				err = ue.Unwrap()
			}
			logger.Debug("Unable to parse remote repository url", log.String("id", rep.ID), log.Err(err))
			continue
		}

		logger.Debug("Adding repository", log.String("id", rep.ID), log.String("url", repoURL.Redacted()))
		r.url = *repoURL
		repos = append(repos, r)
	}
	return repos
}
