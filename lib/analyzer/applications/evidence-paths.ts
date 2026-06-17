import { posix as path } from "path";
import { JarFingerprintsFact, TestedFilesFact } from "../../facts";
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
      for (const filePath of testedFilesFact.data) {
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
