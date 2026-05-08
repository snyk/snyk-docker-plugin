// Package response assembles PluginResponse from analysis results.
package response

import "github.com/snyk/snyk-docker-plugin/pkg/types"

// BuildResponse constructs a PluginResponse from all gathered facts.
// TODO: full implementation.
func BuildResponse(facts []types.Fact, target types.ContainerTarget, identity types.Identity) *types.PluginResponse {
	return &types.PluginResponse{
		ScanResults: []types.ScanResult{
			{
				Target:   target,
				Identity: identity,
				Facts:    facts,
			},
		},
	}
}
