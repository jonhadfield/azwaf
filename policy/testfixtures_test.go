package policy

// loadBackupsFromPathsForTest loads Front Door policy backups from the given
// paths. It replaces the exported LoadBackupsFromPaths, which the production
// code had stopped using — LoadAllBackupsFromPaths supersedes it — but which
// the tests still relied on to load fixtures. Keeping it as a test helper takes
// it out of the package's public surface without churning every call site.
func loadBackupsFromPathsForTest(paths []string) ([]WrappedPolicy, error) {
	loaded, err := LoadAllBackupsFromPaths(paths)
	if err != nil {
		return nil, err
	}

	return loaded.FrontDoor, nil
}
