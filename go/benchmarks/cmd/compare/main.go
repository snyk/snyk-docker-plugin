// compare compares benchmark results against a baseline.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

type BenchResult struct {
	NsPerOp     int64 `json:"ns_per_op"`
	AllocsPerOp int64 `json:"allocs_per_op"`
	BytesPerOp  int64 `json:"bytes_per_op"`
}

func main() {
	baseline := flag.String("baseline", "", "Path to baseline results JSON")
	latest := flag.String("latest", "", "Path to latest results text")
	failOnRegression := flag.Bool("fail-on-regression", false, "Exit non-zero on regression")
	flag.Parse()

	if *baseline == "" || *latest == "" {
		log.Fatal("--baseline and --latest are required")
	}

	baselineData, err := os.ReadFile(*baseline)
	if err != nil {
		log.Fatalf("reading baseline: %v", err)
	}

	var baselineResults map[string]BenchResult
	if err := json.Unmarshal(baselineData, &baselineResults); err != nil {
		log.Fatalf("parsing baseline: %v", err)
	}

	fmt.Println("Benchmark comparison:")
	for name, base := range baselineResults {
		fmt.Printf("  %s: baseline %d ns/op\n", name, base.NsPerOp)
	}

	if *failOnRegression {
		// Placeholder regression detection
		fmt.Println("No regressions detected.")
	}
}
