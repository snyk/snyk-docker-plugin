import { posix as path } from "path";
import { JarFingerprintsFact, TestedFilesFact } from "../../facts";
import { OwnershipCandidate } from "../package-managers/apk-ownership";
import { AppDepsScanResultWithoutTarget } from "./types";

/** Collect filesystem paths from an app scan result used to resolve APK ownership. */
export function extractEvidencePaths(
  scanResult: AppDepsScanResultWithoutTarget,
): string[] {
  const paths = new Set<string>();

  // Some analyzers emit testedFiles as bare basenames (e.g. "composer.json").
  // Anchor those to the app directory so they become real image paths instead
  // of being rooted at "/" downstream, which never matches an APK file list.
  const baseDir = scanResult.identity.targetFile
    ? path.dirname(scanResult.identity.targetFile)
    : undefined;
  const addPath = (filePath: string) => {
    if (filePath.startsWith("/")) {
      paths.add(filePath);
    } else if (baseDir) {
      paths.add(path.join(baseDir, filePath));
    }
  };

  if (scanResult.identity.targetFile) {
    addPath(scanResult.identity.targetFile);
  }

  for (const fact of scanResult.facts) {
    if (fact.type === "testedFiles") {
      const testedFilesFact = fact as TestedFilesFact;
      // Some analyzers (node, pnpm) emit data as a bare string rather than the
      // declared string[]. Treat a string as a single path so it isn't iterated
      // character-by-character into bogus paths.
      const testedFiles =
        typeof testedFilesFact.data === "string"
          ? [testedFilesFact.data as string]
          : testedFilesFact.data;
      for (const filePath of testedFiles) {
        addPath(filePath);
      }
    }

    if (fact.type === "jarFingerprints") {
      const jarFact = fact as JarFingerprintsFact;
      for (const fingerprint of jarFact.data.fingerprints) {
        if (fingerprint.location) {
          addPath(fingerprint.location);
        }
      }
    }
  }

  return [...paths];
}

/**
 * Build the ownership units for an app scan result, each resolved independently
 * by resolveApkOwnership:
 * - npm global modules: one unit per package, keyed by its own install dir. The
 *   shared node_modules root is declared by several apk packages, so only each
 *   package's own dir resolves to a single owner.
 * - Java jars, Go binaries, everything else: a single whole-result unit over the
 *   result's evidence paths — owned only when one apk package owns them all
 *   (fail closed), the same whole-result behavior #872 introduced.
 */
export function buildOwnershipCandidates(
  scanResult: AppDepsScanResultWithoutTarget,
): OwnershipCandidate[] {
  const npmPackages = scanResult.nodeModulesPackagePaths;
  if (npmPackages && npmPackages.length > 0) {
    return npmPackages.map((pkg) => ({
      evidencePaths: [pkg.installDir],
      name: pkg.name,
      version: pkg.version,
    }));
  }

  const evidencePaths = extractEvidencePaths(scanResult);
  return evidencePaths.length > 0 ? [{ evidencePaths }] : [];
}
