import {
  buildOwnershipCandidates,
  extractEvidencePaths,
} from "../../lib/analyzer/applications/evidence-paths";
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
        // basename testedFiles are anchored to the app directory, not "/"
        "/app/package-lock.json",
        "/app/lib/foo.jar",
      ]),
    );
  });

  it("anchors basename testedFiles to the app directory of targetFile", () => {
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "composer", targetFile: "/srv/app/composer.lock" },
      facts: [
        { type: "testedFiles", data: ["composer.json", "composer.lock"] },
      ],
    };

    expect(extractEvidencePaths(scanResult).sort()).toEqual([
      "/srv/app/composer.json",
      "/srv/app/composer.lock",
    ]);
  });

  it("treats a string testedFiles value as a single path, not characters", () => {
    // The npm/pnpm analyzers emit testedFiles.data as a bare string (the global
    // node_modules dir), violating the string[] contract. It must be read as one
    // path, not iterated character-by-character into garbage like "/", "/usr/lib/u".
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "npm", targetFile: "/usr/lib/node_modules" },
      facts: [{ type: "testedFiles", data: "/usr/lib/node_modules" as any }],
    };

    expect(extractEvidencePaths(scanResult)).toEqual(["/usr/lib/node_modules"]);
  });

  it("skips relative testedFiles when there is no targetFile to anchor to", () => {
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "composer" },
      facts: [
        { type: "testedFiles", data: ["composer.json", "/abs/path.jar"] },
      ],
    };

    expect(extractEvidencePaths(scanResult)).toEqual(["/abs/path.jar"]);
  });
});

describe("buildOwnershipCandidates", () => {
  it("emits one coordinate-bearing candidate per npm global package", () => {
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "npm", targetFile: "/usr/lib/node_modules" },
      facts: [{ type: "testedFiles", data: "/usr/lib/node_modules" as any }],
      nodeModulesPackagePaths: [
        {
          name: "brace-expansion",
          version: "2.0.1",
          installDir: "/usr/lib/node_modules/npm/node_modules/brace-expansion",
        },
        {
          name: "semver",
          version: "7.6.0",
          installDir: "/usr/lib/node_modules/npm/node_modules/semver",
        },
      ],
    };

    expect(buildOwnershipCandidates(scanResult)).toEqual([
      {
        evidencePaths: [
          "/usr/lib/node_modules/npm/node_modules/brace-expansion",
        ],
        name: "brace-expansion",
        version: "2.0.1",
      },
      {
        evidencePaths: ["/usr/lib/node_modules/npm/node_modules/semver"],
        name: "semver",
        version: "7.6.0",
      },
    ]);
  });

  it("emits a single whole-result candidate (no coordinate) for jars/Go/other", () => {
    // Java jars and Go binaries resolve as one whole-result unit — owned only
    // when one apk package owns every evidence path. No per-coordinate split.
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "gomodules", targetFile: "/usr/bin/manager" },
      facts: [
        { type: "testedFiles", data: ["/usr/bin/manager"] },
        {
          type: "jarFingerprints",
          data: {
            origin: "image",
            path: "/usr/share/java/maven/lib",
            fingerprints: [
              { location: "/usr/share/java/maven/lib/asm-9.9.1.jar" } as any,
            ],
          },
        },
      ],
    };

    expect(buildOwnershipCandidates(scanResult)).toEqual([
      {
        evidencePaths: [
          "/usr/bin/manager",
          "/usr/share/java/maven/lib/asm-9.9.1.jar",
        ],
      },
    ]);
  });

  it("returns no candidates when there is no ownership evidence", () => {
    const scanResult: AppDepsScanResultWithoutTarget = {
      identity: { type: "composer" },
      facts: [{ type: "testedFiles", data: ["composer.json"] }],
    };

    expect(buildOwnershipCandidates(scanResult)).toEqual([]);
  });
});
