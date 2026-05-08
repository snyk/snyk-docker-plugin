package packages

import "fmt"

// RPMPackage represents a single package from an RPM database.
type RPMPackage struct {
	Name    string
	Version string
	Release string
	Arch    string
	Epoch   int
}

// FullVersion returns the epoch:version-release string.
func (p RPMPackage) FullVersion() string {
	if p.Epoch > 0 {
		return fmt.Sprintf("%d:%s-%s", p.Epoch, p.Version, p.Release)
	}
	return p.Version + "-" + p.Release
}

// ParseRPMSQLite parses an RPM SQLite database (rpmdb.sqlite).
// TODO: implement using modernc.org/sqlite
func ParseRPMSQLite(_ string) ([]RPMPackage, error) {
	// Placeholder — full implementation in a follow-up.
	return nil, nil
}
