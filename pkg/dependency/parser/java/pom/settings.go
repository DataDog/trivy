package pom

const trueString = "true"

// Server and Mirror are the settings.xml entries that resolveMirrors takes.
// NewParser passes nil for both, so its mirrors come from Trivy's config
// file alone.
type Server struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}

type Mirror struct {
	ID       string `xml:"id"`
	Name     string `xml:"name"`
	URL      string `xml:"url"`
	MirrorOf string `xml:"mirrorOf"`
}
