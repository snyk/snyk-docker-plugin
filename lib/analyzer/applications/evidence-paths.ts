import { JarFingerprintsFact, TestedFilesFact } from "../../facts";
import { AppDepsScanResultWithoutTarget } from "./types";

export function extractEvidencePaths(
  scanResult: AppDepsScanResultWithoutTarget,
): string[] {
  const paths = new Set<string>();

  if (scanResult.identity.targetFile) {
    paths.add(scanResult.identity.targetFile);
  }

  for (const fact of scanResult.facts) {
    if (fact.type === "testedFiles") {
      const testedFilesFact = fact as TestedFilesFact;
      for (const filePath of testedFilesFact.data) {
        paths.add(filePath);
      }
    }

    if (fact.type === "jarFingerprints") {
      const jarFact = fact as JarFingerprintsFact;
      for (const fingerprint of jarFact.data.fingerprints) {
        if (fingerprint.location) {
          paths.add(fingerprint.location);
        }
      }
    }
  }

  return [...paths];
}
