// Binary snyk-docker-plugin is a standalone CLI entry point for the Go
// implementation of snyk-docker-plugin. It reads a JSON-encoded PluginOptions
// object from stdin and writes a JSON-encoded PluginResponse to stdout,
// allowing it to be used as a subprocess by the Node.js shim.
//
// Protocol:
//   stdin:  JSON PluginOptions  (or {} for empty options)
//   stdout: JSON PluginResponse
//   stderr: human-readable log / error messages
//   exit:   0 on success, 1 on scan error
//
// The binary also supports a --display mode:
//   stdin:  JSON { scanResults, testResults, errors, options }
//   stdout: ANSI-coloured display string
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/snyk/snyk-docker-plugin/pkg/display"
	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "snyk-docker-plugin:", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]

	if len(args) > 0 && args[0] == "--display" {
		return runDisplay()
	}
	return runScan()
}

func runScan() error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	var opts types.PluginOptions
	if len(input) > 0 {
		if err := json.Unmarshal(input, &opts); err != nil {
			return fmt.Errorf("decoding options: %w", err)
		}
	}

	resp, err := scan.Scan(context.Background(), opts)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(resp); err != nil {
		return fmt.Errorf("encoding response: %w", err)
	}
	return nil
}

// displayInput is the JSON body accepted by --display mode.
type displayInput struct {
	ScanResults []types.ScanResult `json:"scanResults"`
	TestResults []types.TestResult  `json:"testResults"`
	Errors      []string            `json:"errors"`
	Options     types.Options       `json:"options"`
}

func runDisplay() error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	var d displayInput
	if err := json.Unmarshal(input, &d); err != nil {
		return fmt.Errorf("decoding display input: %w", err)
	}

	result, err := display.Display(d.ScanResults, d.TestResults, d.Errors, d.Options)
	if err != nil {
		return fmt.Errorf("display: %w", err)
	}

	_, err = fmt.Fprint(os.Stdout, result)
	return err
}
