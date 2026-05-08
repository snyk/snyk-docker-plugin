// Package depgraph provides DepGraph construction helpers, mirroring
// @snyk/dep-graph's legacy.depTreeToGraph() and the JSON wire format.
package depgraph

import (
	"fmt"
	"sort"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

const SchemaVersion = "1.2.0"

// FromDepTree converts a flat list of DepInfo entries into the DepGraphData
// wire format, mirroring @snyk/dep-graph legacy.depTreeToGraph().
//
// pkgManagerName is e.g. "deb", "apk", "rpm", "npm".
// rootName / rootVersion identify the root package (typically the image name/OS version).
// deps is a slice of {Name, Version, Deps} triples already resolved by the parser.
func FromDepTree(pkgManagerName, rootName, rootVersion string, deps []DepInfo) types.DepGraphData {
	// pkgID → Pkg
	pkgsByID := map[string]types.Pkg{}
	// nodeID → Node
	nodesByID := map[string]types.Node{}
	// counter for |N suffix dedup
	nodeCounter := map[string]int{}

	rootPkgID := pkgID(rootName, rootVersion)
	const rootNodeID = "root-node"

	pkgsByID[rootPkgID] = types.Pkg{
		ID:   rootPkgID,
		Info: types.PkgInfo{Name: rootName, Version: rootVersion},
	}

	rootNode := types.Node{
		NodeID: rootNodeID,
		PkgID:  rootPkgID,
		Deps:   []types.DepRef{},
	}

	for _, dep := range deps {
		nid := addPackage(dep, pkgsByID, nodesByID, nodeCounter)
		rootNode.Deps = append(rootNode.Deps, types.DepRef{NodeID: nid})
	}

	// stable ordering
	pkgs := make([]types.Pkg, 0, len(pkgsByID))
	for _, p := range pkgsByID {
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID })

	nodes := make([]types.Node, 0, len(nodesByID)+1)
	nodes = append(nodes, rootNode)
	nodeIDs := make([]string, 0, len(nodesByID))
	for nid := range nodesByID {
		nodeIDs = append(nodeIDs, nid)
	}
	sort.Strings(nodeIDs)
	for _, nid := range nodeIDs {
		nodes = append(nodes, nodesByID[nid])
	}

	return types.DepGraphData{
		SchemaVersion: SchemaVersion,
		PkgManager:    types.PkgManager{Name: pkgManagerName},
		Pkgs:          pkgs,
		Graph: types.Graph{
			RootNodeID: rootNodeID,
			Nodes:      nodes,
		},
	}
}

// DepInfo is a flat dependency entry used by the builder.
type DepInfo struct {
	Name    string
	Version string
	Deps    []DepInfo
}

func pkgID(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

func addPackage(
	dep DepInfo,
	pkgsByID map[string]types.Pkg,
	nodesByID map[string]types.Node,
	nodeCounter map[string]int,
) string {
	pid := pkgID(dep.Name, dep.Version)
	pkgsByID[pid] = types.Pkg{
		ID:   pid,
		Info: types.PkgInfo{Name: dep.Name, Version: dep.Version},
	}

	// First occurrence: nodeID == pkgID; subsequent: pkgID|N
	count := nodeCounter[pid]
	nodeCounter[pid]++
	var nid string
	if count == 0 {
		nid = pid
	} else {
		nid = fmt.Sprintf("%s|%d", pid, count)
	}

	node := types.Node{
		NodeID: nid,
		PkgID:  pid,
		Deps:   []types.DepRef{},
	}
	for _, child := range dep.Deps {
		cnid := addPackage(child, pkgsByID, nodesByID, nodeCounter)
		node.Deps = append(node.Deps, types.DepRef{NodeID: cnid})
	}
	nodesByID[nid] = node
	return nid
}

// PkgCount returns the number of unique non-root packages in a DepGraphData.
func PkgCount(data types.DepGraphData) int {
	if len(data.Pkgs) == 0 {
		return 0
	}
	// Subtract 1 for the root package.
	return len(data.Pkgs) - 1
}
