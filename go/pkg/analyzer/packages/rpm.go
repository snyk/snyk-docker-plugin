package packages

import (
	"fmt"
	"os"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
)

// RPMPackage represents a single installed RPM package.
type RPMPackage struct {
	Name      string
	Version   string // epoch:version-release
	Epoch     *int
	Release   string
	Arch      string
	SourceRPM string
	Purl      string
}

// FullVersion returns the epoch:version-release version string,
// mirroring formatRpmPackageVersion from @snyk/rpm-parser.
func (p RPMPackage) FullVersion() string {
	ver := p.Version
	if p.Release != "" && !strings.HasSuffix(ver, "-"+p.Release) {
		ver = ver + "-" + p.Release
	}
	if p.Epoch != nil && *p.Epoch != 0 {
		ver = fmt.Sprintf("%d:%s", *p.Epoch, ver)
	}
	return ver
}

// ParseRPMBDB reads a BDB-format RPM database from in-memory bytes.
// It writes to a temp file (go-rpmdb requires a real path), parses, then removes it.
func ParseRPMBDB(data []byte) ([]RPMPackage, error) {
	return parseRPMBytes(data)
}

// ParseRPMNDB reads an NDB-format RPM database from in-memory bytes.
func ParseRPMNDB(data []byte) ([]RPMPackage, error) {
	return parseRPMBytes(data)
}

// ParseRPMSQLite reads a SQLite-format RPM database from in-memory bytes.
func ParseRPMSQLite(data []byte) ([]RPMPackage, error) {
	return parseRPMBytes(data)
}

// parseRPMBytes writes data to a temp file, opens it with go-rpmdb
// (which auto-detects BDB/NDB/SQLite), then cleans up.
func parseRPMBytes(data []byte) ([]RPMPackage, error) {
	if len(data) == 0 {
		return nil, nil
	}

	tmp, err := os.CreateTemp("", "snyk-rpm-*.db")
	if err != nil {
		return nil, fmt.Errorf("creating temp rpm db: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing temp rpm db: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing temp rpm db: %w", err)
	}

	db, err := rpmdb.Open(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("opening rpm db: %w", err)
	}
	defer db.Close()

	infos, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("listing rpm packages: %w", err)
	}

	pkgs := make([]RPMPackage, 0, len(infos))
	for _, info := range infos {
		if info == nil || info.Name == "" {
			continue
		}
		p := RPMPackage{
			Name:      info.Name,
			Version:   info.Version,
			Release:   info.Release,
			Arch:      info.Arch,
			SourceRPM: info.SourceRpm,
			Epoch:     info.Epoch,
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// RPMPurl builds a package-URL for an RPM package, mirroring
// lib/analyzer/package-managers/rpm.ts purl().
func RPMPurl(pkg RPMPackage, repos []string, osRel *osrelease.OSRelease) string {
	if pkg.Name == "" || pkg.Version == "" {
		return ""
	}
	var qualifiers []string

	if pkg.SourceRPM != "" {
		if src := parseSourceRPM(pkg.SourceRPM); src.name != "" {
			upstream := src.name
			if src.version != "" && src.release != "" {
				upstream += "@" + src.version + "-" + src.release
			} else if src.version != "" {
				upstream += "@" + src.version
			}
			qualifiers = append(qualifiers, "upstream="+upstream)
		}
	}
	if len(repos) > 0 {
		qualifiers = append(qualifiers, "repositories="+strings.Join(repos, ","))
	}
	if pkg.Epoch != nil && *pkg.Epoch != 0 {
		qualifiers = append(qualifiers, fmt.Sprintf("epoch=%d", *pkg.Epoch))
	}

	vendor := ""
	if osRel != nil {
		qualifiers = append(qualifiers, "distro="+osRel.Name+"-"+osRel.Version)
		vendor = osRel.Name
	}

	q := ""
	if len(qualifiers) > 0 {
		q = "?" + strings.Join(qualifiers, "&")
	}
	return fmt.Sprintf("pkg:rpm/%s/%s@%s%s", vendor, pkg.Name, pkg.FullVersion(), q)
}

type sourceRPM struct {
	name    string
	version string
	release string
}

// parseSourceRPM parses "<name>-<version>-<release>.<arch>.rpm"
// into its components, mirroring parseSourceRPM in rpm.ts.
func parseSourceRPM(src string) sourceRPM {
	// Strip trailing .src.rpm or .rpm
	base := strings.TrimSuffix(src, ".rpm")
	// Split on dots to get arch — last component before potential .rpm
	dotParts := strings.Split(base, ".")
	if len(dotParts) > 1 {
		// Remove the arch suffix (e.g. ".src" or ".x86_64")
		base = strings.Join(dotParts[:len(dotParts)-1], ".")
	}

	// Now base is "<name>-<version>-<release>"
	// Find last hyphen (release boundary) then second-last (version boundary).
	lastHyphen := strings.LastIndex(base, "-")
	if lastHyphen < 0 {
		return sourceRPM{name: base}
	}
	release := base[lastHyphen+1:]
	nameAndVersion := base[:lastHyphen]

	secondLastHyphen := strings.LastIndex(nameAndVersion, "-")
	if secondLastHyphen < 0 {
		return sourceRPM{name: nameAndVersion, release: release}
	}

	return sourceRPM{
		name:    nameAndVersion[:secondLastHyphen],
		version: nameAndVersion[secondLastHyphen+1:],
		release: release,
	}
}
