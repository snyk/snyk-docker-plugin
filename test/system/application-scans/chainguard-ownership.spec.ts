import { scan } from "../../../lib/index";

// Self-hosted on the snykgoof Docker Hub org (mirrored from chainguard/bash)
// since chainguard.dev requires auth to pull non-`latest` tags, which would
// break this in CI.
const BASH_IMAGE =
  "snykgoof/chainguard-bash@sha256:bf932e4dc71966dcab75dae6ec518ff3d1dde8f473ddb7bbaebdaab52b5efae8";
// Digest-pinned for reproducibility and pulled from docker.io, matching the
// registry the rest of the system suite already uses.
const NODE_IMAGE =
  "chainguard/node@sha256:27bf957bdf6d189108c8908c958fd966d9814f78e7172c2d791940f4e208a334";

describe("chainguard app ownership", () => {
  afterAll(async () => {
    // Best-effort cleanup if the images were pulled during the test.
    try {
      const { execute } = await import("../../../lib/sub-process");
      await execute("docker", ["image", "rm", BASH_IMAGE, NODE_IMAGE]);
    } catch {
      // ignore teardown errors
    }
  });

  it("does not attach apkPackageOwnership on OS-only Chainguard images", async () => {
    const pluginResult = await scan({
      path: BASH_IMAGE,
      platform: "linux/amd64",
    });

    const appResults = pluginResult.scanResults.slice(1);
    const ownershipFacts = appResults.flatMap((result) =>
      result.facts.filter((fact) => fact.type === "apkPackageOwnership"),
    );
    expect(ownershipFacts).toHaveLength(0);
  });

  it("attaches per-dependency npm ownership for apk-bundled node packages", async () => {
    // npm bundles its own dependency tree under
    // /usr/lib/node_modules/npm/node_modules, owned by the `npm` apk package.
    // Those deps must be reconciled to origin `npm` rather than reported as
    // unqualified upstream npm findings. Assert the invariant (at least one npm
    // owned dependency) rather than a specific package, which can change across
    // npm releases.
    const pluginResult = await scan({
      path: NODE_IMAGE,
      platform: "linux/amd64",
    });

    const appResults = pluginResult.scanResults.slice(1);
    const ownedPackages = appResults.flatMap((result) =>
      result.facts
        .filter((fact) => fact.type === "apkPackageOwnership")
        .flatMap((fact) => (fact.data as any).ownedPackages),
    );

    const npmOwned = ownedPackages.filter(
      (pkg: any) => pkg.originPackage === "npm",
    );
    expect(npmOwned.length).toBeGreaterThan(0);

    // The internal install-dir data must never reach the public output —
    // neither as a fact nor as a field on the ScanResult.
    const carrierFacts = appResults.flatMap((result) =>
      result.facts.filter((fact) => fact.type === "nodeModulesPackagePaths"),
    );
    expect(carrierFacts).toHaveLength(0);
    appResults.forEach((result) => {
      expect((result as any).nodeModulesPackagePaths).toBeUndefined();
    });
  });
});
