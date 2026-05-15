package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	dockerplugin "github.com/snyk/snyk-docker-plugin/extension-adapter"
)

func main() {
	image := "oci-archive:/work/snyk-docker-plugin/test/fixtures/oci-archives/busybox-1.31.1.tar"
	if len(os.Args) > 1 {
		image = os.Args[1]
	}

	// Create engine
	engine := app.CreateAppEngineWithOptions()
	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("test"), runtimeinfo.WithVersion("0.0.0")))

	config := engine.GetConfiguration()
	config.Set(configuration.INPUT_DIRECTORY, image)
	config.Set("targetDirectory", image)

	// Register our plugin
	if err := dockerplugin.Init(engine); err != nil {
		fmt.Fprintf(os.Stderr, "Init failed: %v\n", err)
		os.Exit(1)
	}

	// Initialize the engine
	if err := engine.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "engine.Init failed: %v\n", err)
		os.Exit(1)
	}

	// Invoke the workflow
	wfID := workflow.NewWorkflowIdentifier("container depgraph")
	results, err := engine.InvokeWithConfig(wfID, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "InvokeWithConfig failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Got %d results\n", len(results))
	for i, r := range results {
		loc, _ := r.GetMetaData("Content-Location")
		payload := r.GetPayload()
		switch v := payload.(type) {
		case []byte:
			var pretty interface{}
			if json.Unmarshal(v, &pretty) == nil {
				b, _ := json.MarshalIndent(pretty, "", "  ")
				fmt.Printf("=== Result %d (type=%s, location=%s) ===\n%s\n",
					i, r.GetContentType(), loc, string(b))
			} else {
				fmt.Printf("=== Result %d raw ===\n%s\n", i, string(v))
			}
		default:
			fmt.Printf("=== Result %d (type=%T) ===\n%v\n", i, payload, payload)
		}
	}
}
