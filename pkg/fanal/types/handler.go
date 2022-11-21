package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	DpkgPostHandler                HandlerType = "dpkg"
	UnpackagedPostHandler          HandlerType = "unpackaged"

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100
	DpkgPostHandlerPriority                = 50
	UnpackagedPostHandlerPriority          = 50
)
