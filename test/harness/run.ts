#!/usr/bin/env ts-node
/**
 * Plugin harness — exercise the scan() API from the command line.
 *
 * Usage:
 *   ts-node test/harness/run.ts [options] <image-or-archive>
 *
 * Examples:
 *   ts-node test/harness/run.ts docker-archive:test/fixtures/docker-archives/docker-save/nginx.tar
 *   ts-node test/harness/run.ts --output /tmp/out.json --fact layerPackageAttribution docker-archive:test/fixtures/...
 *   ts-node test/harness/run.ts --platform linux/arm64 alpine:3.19
 *   ts-node test/harness/run.ts --username user --password pass registry.example.com/image:tag
 */

import * as fs from "fs";
import * as path from "path";
import { scan } from "../../lib/scan";
import { Fact, PluginOptions } from "../../lib/types";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

interface Args {
  image: string;
  output?: string;
  facts: string[];
  compact: boolean;
  pluginOptions: Partial<PluginOptions>;
}

function printHelp(): void {
  console.log(`
Usage: ts-node test/harness/run.ts [options] <image-or-archive>

  <image-or-archive>  Image identifier (e.g. "alpine:3.19") or a prefixed
                      archive path:
                        docker-archive:/path/to/image.tar
                        oci-archive:/path/to/image.tar
                        kaniko-archive:/path/to/image.tar

Options:
  --file <path>                 Path to a Dockerfile for Dockerfile analysis
  --platform <os/arch>          Target platform, e.g. linux/amd64 (default)
  --username <user>             Registry username (or set SNYK_REGISTRY_USERNAME)
  --password <pass>             Registry password (or set SNYK_REGISTRY_PASSWORD)
  --image-name <name:tag>       Override image name/tag for archive scans
  --exclude-app-vulns           Exclude application vulnerability scanning
  --exclude-base-image-vulns    Exclude base image packages from results
  --exclude-node-modules        Skip node_modules scanning
  --nested-jars-depth <n>       Depth for nested JAR unpacking (default: 1)
  --collect-application-files   Collect application file metadata
  --layer-attribution           Compute per-layer package attribution (adds layerPackageAttribution fact)

  --output <file>               Write JSON output to file instead of stdout
  --compact                     Compact JSON (default: pretty-printed)
  --fact <type>                 Show only this fact type (repeatable).
                                e.g. --fact depGraph --fact layerPackageAttribution
  --help                        Show this message
`);
}

function parseArgs(argv: string[]): Args {
  const args = argv.slice(2);
  const pluginOptions: Partial<PluginOptions> = {};
  const facts: string[] = [];
  let output: string | undefined;
  let compact = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = () => {
      if (i + 1 >= args.length || args[i + 1].startsWith("--")) {
        throw new Error(`${arg} requires a value`);
      }
      return args[++i];
    };

    switch (arg) {
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
        break;
      case "--file":
        pluginOptions.file = next();
        break;
      case "--platform":
        pluginOptions.platform = next();
        break;
      case "--username":
        pluginOptions.username = next();
        break;
      case "--password":
        pluginOptions.password = next();
        break;
      case "--image-name":
        pluginOptions.imageNameAndTag = next();
        break;
      case "--exclude-app-vulns":
        pluginOptions["exclude-app-vulns"] = true;
        break;
      case "--exclude-base-image-vulns":
        pluginOptions["exclude-base-image-vulns"] = true;
        break;
      case "--exclude-node-modules":
        pluginOptions["exclude-node-modules"] = true;
        break;
      case "--nested-jars-depth":
        pluginOptions["nested-jars-depth"] = next();
        break;
      case "--collect-application-files":
        pluginOptions["collect-application-files"] = true;
        break;
      case "--layer-attribution":
        pluginOptions["layer-attribution"] = true;
        break;
      case "--output":
        output = next();
        break;
      case "--compact":
        compact = true;
        break;
      case "--fact":
        facts.push(next());
        break;
      default:
        if (arg.startsWith("--")) {
          console.error(`Unknown option: ${arg}`);
          printHelp();
          process.exit(1);
        }
        // Positional: the image/archive path
        if (pluginOptions.path) {
          console.error("Unexpected extra argument: " + arg);
          process.exit(1);
        }
        pluginOptions.path = arg;
    }
  }

  if (!pluginOptions.path) {
    console.error("Error: <image-or-archive> is required\n");
    printHelp();
    process.exit(1);
  }

  return { image: pluginOptions.path, output, facts, compact, pluginOptions };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { output, facts, compact, pluginOptions } = parseArgs(process.argv);

  let result;
  try {
    result = await scan(pluginOptions);
  } catch (err: any) {
    console.error("Scan failed:", err.message || err);
    process.exit(1);
  }

  // Filter to requested fact types if --fact was given
  if (facts.length > 0) {
    const factSet = new Set(facts);
    result = {
      scanResults: result.scanResults.map((sr) => ({
        ...sr,
        facts: sr.facts.filter((f: Fact) => factSet.has(f.type)),
      })),
    };
  }

  const json = compact
    ? JSON.stringify(result)
    : JSON.stringify(result, null, 2);

  if (output) {
    const dest = path.resolve(output);
    fs.writeFileSync(dest, json, "utf8");
    console.error(`Output written to ${dest}`);
  } else {
    process.stdout.write(json + "\n");
  }
}

main();
