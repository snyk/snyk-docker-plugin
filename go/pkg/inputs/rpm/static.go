// Package rpm provides ExtractActions for RPM package database files.
// Three database formats are supported: BDB (Packages), NDB (Packages.db), SQLite (rpmdb.sqlite).
package rpm

import "github.com/snyk/snyk-docker-plugin/pkg/extractor"

const (
	ActionNameBDB    = "rpm-db"
	ActionNameNDB    = "rpm-ndb"
	ActionNameSQLite = "rpm-sqlite-db"
)

// BDBAction extracts the Berkeley DB RPM database (classic format).
var BDBAction = extractor.ExtractAction{
	ActionName: ActionNameBDB,
	FilePathMatches: func(p string) bool {
		return p == "/var/lib/rpm/Packages" ||
			p == "/usr/lib/sysimage/rpm/Packages"
	},
}

// NDBAction extracts the NDB-format RPM database.
var NDBAction = extractor.ExtractAction{
	ActionName: ActionNameNDB,
	FilePathMatches: func(p string) bool {
		return p == "/var/lib/rpm/Packages.db" ||
			p == "/usr/lib/sysimage/rpm/Packages.db"
	},
}

// SQLiteAction extracts the SQLite RPM database.
var SQLiteAction = extractor.ExtractAction{
	ActionName: ActionNameSQLite,
	FilePathMatches: func(p string) bool {
		return p == "/var/lib/rpm/rpmdb.sqlite" ||
			p == "/usr/lib/sysimage/rpm/rpmdb.sqlite"
	},
}

// Actions returns all ExtractActions needed for RPM analysis.
func Actions() []extractor.ExtractAction {
	return []extractor.ExtractAction{BDBAction, NDBAction, SQLiteAction}
}
