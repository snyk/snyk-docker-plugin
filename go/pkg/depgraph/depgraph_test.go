package depgraph_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFromDepTree_empty(t *testing.T) {
	graph := depgraph.FromDepTree("deb", "debian:11", "11", nil)
	assert.Equal(t, depgraph.SchemaVersion, graph.SchemaVersion)
	assert.Equal(t, "deb", graph.PkgManager.Name)
	assert.Equal(t, "root-node", graph.Graph.RootNodeID)
	assert.Len(t, graph.Graph.Nodes, 1, "only root node")
	assert.Equal(t, []types.DepRef{}, graph.Graph.Nodes[0].Deps)
}

func TestFromDepTree_simple(t *testing.T) {
	deps := []depgraph.DepInfo{
		{Name: "curl", Version: "7.68.0"},
		{Name: "libssl", Version: "1.1.1"},
	}
	graph := depgraph.FromDepTree("deb", "debian:11", "11", deps)
	assert.Equal(t, depgraph.SchemaVersion, graph.SchemaVersion)
	// root + 2 deps
	assert.Len(t, graph.Pkgs, 3)
	assert.Len(t, graph.Graph.Nodes, 3)
	assert.Len(t, graph.Graph.Nodes[0].Deps, 2, "root has 2 deps")
	assert.Equal(t, 2, depgraph.PkgCount(graph))
}

func TestFromDepTree_deterministic(t *testing.T) {
	deps := []depgraph.DepInfo{
		{Name: "z-pkg", Version: "1"},
		{Name: "a-pkg", Version: "1"},
	}
	// Run twice, expect identical JSON ordering
	g1 := depgraph.FromDepTree("apk", "alpine:3.12", "3.12", deps)
	g2 := depgraph.FromDepTree("apk", "alpine:3.12", "3.12", deps)
	assert.Equal(t, g1, g2)
}

func TestPkgCount_zero(t *testing.T) {
	assert.Equal(t, 0, depgraph.PkgCount(types.DepGraphData{}))
}
