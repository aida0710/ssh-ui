package storage

import "ssh-ui/internal/config"

// ConfigLoader gives the Include graph read-only access to the disk.
//
// It deliberately reads files outside the workspace root, because the design
// requires showing an Include that points elsewhere, but it never follows a
// symbolic link and never writes. Only Workspace.ResolveForWrite decides what
// may be modified.
type ConfigLoader struct {
	fileSystem FileSystem
}

func NewConfigLoader(workspace *Workspace) ConfigLoader {
	return ConfigLoader{fileSystem: workspace.FileSystem()}
}

func (l ConfigLoader) ReadFile(path string) ([]byte, error) {
	return l.fileSystem.ReadFile(path)
}

func (l ConfigLoader) Glob(pattern string) ([]string, error) {
	return l.fileSystem.Glob(pattern)
}

// NewResolver builds the Include resolver for a workspace.
//
// Only '%d' is supplied as a percent token. '%u' and '%i' need the local user
// name and uid, which the platform layer provides in a later subsystem; until
// then those patterns are reported as unsupported instead of being guessed.
func NewResolver(workspace *Workspace) config.Resolver {
	return config.Resolver{
		Loader: NewConfigLoader(workspace),
		Home:   workspace.Home(),
		Root:   workspace.Root(),
		Tokens: map[byte]string{'d': workspace.Home()},
	}
}
