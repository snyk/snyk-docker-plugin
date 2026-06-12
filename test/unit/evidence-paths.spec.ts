import { extractEvidencePaths } from "../../lib/analyzer/applications/evidence-paths";
import { AppDepsScanResultWithoutTarget } from "../../lib/analyzer/applications/types";

describe("evidence-paths", () => {
  it("collects targetFile, testedFiles, and jar fingerprint locations", () => {
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "npm", targetFile: "/app/package.json" },
      facts: [
        { type: "testedFiles", data: ["package-lock.json"] },
        {
          type: "jarFingerprints",
          data: {
            origin: "image",
            path: "/app/lib",
            fingerprints: [{ location: "/app/lib/foo.jar" } as any],
          },
        },
      ],
    };

    expect(extractEvidencePaths(scanResult)).toEqual(
      expect.arrayContaining([
        "/app/package.json",
        "package-lock.json",
        "/app/lib/foo.jar",
      ]),
    );
  });
});
