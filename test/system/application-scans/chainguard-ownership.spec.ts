import { scan } from "../../../lib/index";

// Self-hosted on the snykgoof Docker Hub org (mirrored from chainguard/bash,
// preserving the original multi-arch amd64+arm64 manifest index) since
// chainguard.dev requires auth to pull non-`latest` tags, which would break
// this in CI. The mirror was pushed with `docker buildx imagetools create`,
// which copies the manifest index verbatim, so the digest is unchanged.
const BASH_IMAGE =
  "snykgoof/chainguard-bash@sha256:642933df66209814502599053ca3dfa97cccf847badc4219d2b1fd6565f6559a";
// Self-hosted on the snykgoof Docker Hub org (mirrored from chainguard/node)
// for the same reason as BASH_IMAGE above.
const NODE_IMAGE =
  "snykgoof/chainguard-node@sha256:27bf957bdf6d189108c8908c958fd966d9814f78e7172c2d791940f4e208a334";

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

    // The internal install-dir data must never reach the public ScanResult.
    appResults.forEach((result) => {
      expect((result as any).nodeModulesPackagePaths).toBeUndefined();
    });
  });
});
