import {
  checkHistoryAlignment,
  computeOsLayerAttribution,
  computeOsPackageManagerLayerAttribution,
} from "../../../lib/analyzer/layer-attribution";
import {
  AnalysisType,
  ImagePackagesAnalysis,
} from "../../../lib/analyzer/types";
import { ExtractedLayers, HistoryEntry } from "../../../lib/extractor/types";

const image = "test-image:latest";
const emptyLayer: ExtractedLayers = {};

// Minimal APK "installed" DB: repeated "P:<name>\nV:<version>" stanzas, with
// an optional `o:<origin>` (source) line.
function makeApkDb(
  ...pkgs: Array<{ name: string; version: string; origin?: string }>
): string {
  return (
    pkgs
      .map(
        (p) =>
          [
            `P:${p.name}`,
            `V:${p.version}`,
            ...(p.origin ? [`o:${p.origin}`] : []),
          ].join("\n") + "\n",
      )
      .join("\n") + "\n"
  );
}

// Minimal dpkg "status" DB. `Source` is what makes the dep-graph name
// `<source>/<binary>` rather than just `<binary>`.
function makeDpkgStatus(
  ...pkgs: Array<{ name: string; version: string; source?: string }>
): string {
  return pkgs
    .map(
      (p) =>
        [
          `Package: ${p.name}`,
          "Status: install ok installed",
          ...(p.source ? [`Source: ${p.source}`] : []),
          `Version: ${p.version}`,
        ].join("\n") + "\n",
    )
    .join("\n");
}

const makeApkLayer = (db: string): ExtractedLayers => ({
  "/lib/apk/db/installed": { "apk-db": db },
});
const makeAptLayer = (db: string): ExtractedLayers => ({
  "/var/lib/dpkg/status": { dpkg: db },
});

// Hides the fixed image/osRelease/redHatRepositories args so each test shows
// only the layers and diffIDs that matter.
const attribute = (
  analysisType: AnalysisType,
  orderedLayers: ExtractedLayers[],
  diffIDs: string[],
) =>
  computeOsPackageManagerLayerAttribution(
    orderedLayers,
    analysisType,
    diffIDs,
    image,
    undefined,
    [],
  );

const h = (created_by: string, empty_layer = false): HistoryEntry => ({
  created_by,
  empty_layer,
});

describe("checkHistoryAlignment", () => {
  // The backend owns the diffID -> instruction-text join; the plugin only
  // surfaces a warning when the OCI rule "non-empty history maps 1:1 to
  // rootfs.diff_ids[]" is broken. The per-package diffID labels are correct
  // either way, so an absent history is "nothing to join", not an error.
  it.each<[string, string[], HistoryEntry[] | null | undefined]>([
    [
      "history matches rootFs length",
      ["sha256:a", "sha256:b"],
      [h("FROM alpine"), h("RUN apk add curl")],
    ],
    [
      "empty_layer entries are ignored",
      ["sha256:a", "sha256:b"],
      [h("FROM alpine"), h("ENV PATH=/bin", true), h("RUN apk add curl")],
    ],
    ["history is null", ["sha256:a"], null],
    ["history is undefined", ["sha256:a"], undefined],
    ["the image is empty", [], []],
  ])("returns no warning when %s", (_desc, rootFs, history) => {
    expect(checkHistoryAlignment(rootFs, history)).toBeUndefined();
  });

  it("warns when the non-empty history count differs from rootFs length", () => {
    const warning = checkHistoryAlignment(
      ["sha256:a", "sha256:b", "sha256:c"],
      [h("FROM alpine"), h("RUN apk add curl")],
    );
    expect(warning).toContain("does not align");
    expect(warning).toContain("history has 2");
    expect(warning).toContain("rootfs has 3");
  });
});

describe("computeOsPackageManagerLayerAttribution", () => {
  const libc = { name: "libc", version: "2.35-r1" };
  const curl = { name: "curl", version: "7.0.0-r0" };
  const nginx = { name: "nginx", version: "1.24.0-r0" };

  it("attributes each package to the layer that introduced it", async () => {
    const result = await attribute(
      AnalysisType.Apk,
      [makeApkLayer(makeApkDb(libc)), makeApkLayer(makeApkDb(libc, nginx))],
      ["sha256:base", "sha256:nginx-layer"],
    );

    expect(result.get("libc@2.35-r1")).toBe("sha256:base");
    expect(result.get("nginx@1.24.0-r0")).toBe("sha256:nginx-layer");
  });

  it("treats a layer with no DB file as 'no change', not a reset", async () => {
    // The empty COPY/ENV layer must not reset state: libc stays attributed
    // to its original layer, and nginx (added afterwards) to its own.
    const result = await attribute(
      AnalysisType.Apk,
      [
        makeApkLayer(makeApkDb(libc)),
        emptyLayer,
        makeApkLayer(makeApkDb(libc, nginx)),
      ],
      ["sha256:a", "sha256:b", "sha256:c"],
    );

    expect(result.get("libc@2.35-r1")).toBe("sha256:a");
    expect(result.get("nginx@1.24.0-r0")).toBe("sha256:c");
  });

  it("treats an empty DB file as a wipe, re-attributing reinstalls to the latest layer", async () => {
    // An empty (but present) DB means every package was removed, so a later
    // reinstall is a fresh install. Only the surviving copy's layer counts.
    const result = await attribute(
      AnalysisType.Apk,
      [
        makeApkLayer(makeApkDb(curl)),
        makeApkLayer(""),
        makeApkLayer(makeApkDb(curl)),
        makeApkLayer(""),
        makeApkLayer(makeApkDb(curl)),
      ],
      ["sha256:l0", "sha256:l1", "sha256:l2", "sha256:l3", "sha256:l4"],
    );

    expect(result.get("curl@7.0.0-r0")).toBe("sha256:l4");
  });

  it("excludes packages that were removed and not reinstalled", async () => {
    // L0 installs curl + libc; L1 removes curl. Only libc survives on disk.
    const result = await attribute(
      AnalysisType.Apk,
      [makeApkLayer(makeApkDb(curl, libc)), makeApkLayer(makeApkDb(libc))],
      ["sha256:a", "sha256:b"],
    );

    expect(result.has("curl@7.0.0-r0")).toBe(false);
    expect(result.get("libc@2.35-r1")).toBe("sha256:a");
  });

  it("returns an empty map when no layer has a package DB", async () => {
    const result = await attribute(
      AnalysisType.Apk,
      [emptyLayer, emptyLayer],
      ["sha256:a", "sha256:b"],
    );
    expect(result.size).toBe(0);
  });

  it("throws when orderedLayers and diffIDs lengths disagree", async () => {
    // Both arrays describe the same rootfs layers; a mismatch is an internal
    // invariant violation, so fail loudly rather than mis-attribute.
    await expect(
      attribute(
        AnalysisType.Apk,
        [makeApkLayer(makeApkDb(libc)), makeApkLayer(makeApkDb(libc))],
        ["sha256:a"],
      ),
    ).rejects.toThrow(/orderedLayers \(2\) and diffIDs \(1\) must align/);
  });

  // Keys must match the dep-graph node name (`${depFullName}@${version}`) so
  // response-builder can join them; the source/origin prefix is the part most
  // likely to drift, so assert it per package manager.
  it("keys apk packages by `<origin>/<binary>` when an origin is present", async () => {
    const result = await attribute(
      AnalysisType.Apk,
      [
        makeApkLayer(
          makeApkDb({
            name: "libcrypto3",
            version: "3.0.7-r0",
            origin: "openssl",
          }),
        ),
      ],
      ["sha256:a"],
    );

    expect(result.get("openssl/libcrypto3@3.0.7-r0")).toBe("sha256:a");
    expect(result.has("libcrypto3@3.0.7-r0")).toBe(false);
  });

  it("keys apt packages by `<source>/<binary>` when a Source is present", async () => {
    const result = await attribute(
      AnalysisType.Apt,
      [
        makeAptLayer(
          makeDpkgStatus({
            name: "libc-bin",
            version: "2.36-9+deb12u7",
            source: "glibc",
          }),
        ),
      ],
      ["sha256:a"],
    );

    expect(result.get("glibc/libc-bin@2.36-9+deb12u7")).toBe("sha256:a");
    expect(result.has("libc-bin@2.36-9+deb12u7")).toBe(false);
  });
});

describe("computeOsLayerAttribution", () => {
  const curl = { name: "curl", version: "7.0.0-r0" };
  const libc6 = { name: "libc6", version: "2.35-0ubuntu3" };

  function makeAnalysis(
    analyzeType: Exclude<AnalysisType, AnalysisType.Binaries>,
    pkg: { name: string; version: string },
  ): ImagePackagesAnalysis {
    return {
      Image: image,
      AnalyzeType: analyzeType,
      Analysis: [
        { Name: pkg.name, Version: pkg.version, Provides: [], Deps: {} },
      ],
    };
  }

  const apkAndDpkgLayer = (
    apkPkg: { name: string; version: string },
    dpkgPkg: { name: string; version: string },
  ): ExtractedLayers => ({
    "/lib/apk/db/installed": { "apk-db": makeApkDb(apkPkg) },
    "/var/lib/dpkg/status": { dpkg: makeDpkgStatus(dpkgPkg) },
  });

  // Hides the fixed image/osRelease/redHatRepositories args.
  const merge = (
    analyses: ImagePackagesAnalysis[],
    orderedLayers: ExtractedLayers[],
    diffIDs: string[],
  ) =>
    computeOsLayerAttribution(
      analyses,
      orderedLayers,
      diffIDs,
      image,
      undefined,
      [],
    );

  it("processes an ecosystem once even when its analyses repeat", async () => {
    // RPM bdb+sqlite (or apt + distroless-apt) produce two analyses sharing
    // an AnalyzeType. The ecosystem must be attributed once, with no
    // self-collision warning.
    const { introducingLayerByPackage, warnings } = await merge(
      [
        makeAnalysis(AnalysisType.Apk, curl),
        makeAnalysis(AnalysisType.Apk, curl),
      ],
      [makeApkLayer(makeApkDb(curl))],
      ["sha256:a"],
    );

    expect(introducingLayerByPackage.get("curl@7.0.0-r0")).toBe("sha256:a");
    expect(warnings).toEqual([]);
  });

  it("merges attribution across ecosystems on a mixed image", async () => {
    const { introducingLayerByPackage, warnings } = await merge(
      [
        makeAnalysis(AnalysisType.Apk, curl),
        makeAnalysis(AnalysisType.Apt, libc6),
      ],
      [apkAndDpkgLayer(curl, libc6)],
      ["sha256:a"],
    );

    expect(introducingLayerByPackage.get("curl@7.0.0-r0")).toBe("sha256:a");
    expect(introducingLayerByPackage.get("libc6@2.35-0ubuntu3")).toBe(
      "sha256:a",
    );
    expect(warnings).toEqual([]);
  });

  it("ignores ecosystems whose top-level Analysis is empty", async () => {
    const { introducingLayerByPackage } = await merge(
      [
        makeAnalysis(AnalysisType.Apk, curl),
        { Image: image, AnalyzeType: AnalysisType.Rpm, Analysis: [] },
      ],
      [makeApkLayer(makeApkDb(curl))],
      ["sha256:a"],
    );

    expect([...introducingLayerByPackage]).toEqual([
      ["curl@7.0.0-r0", "sha256:a"],
    ]);
  });

  it("returns an empty map when there are no analyses", async () => {
    const { introducingLayerByPackage, warnings } = await merge(
      [],
      [makeApkLayer(makeApkDb(curl))],
      ["sha256:a"],
    );
    expect(introducingLayerByPackage.size).toBe(0);
    expect(warnings).toEqual([]);
  });

  it("records per-ecosystem failures as warnings instead of throwing", async () => {
    // A diffIDs/orderedLayers length mismatch makes every per-PM call throw;
    // the orchestrator must collect the errors and still return.
    const { introducingLayerByPackage, warnings } = await merge(
      [
        makeAnalysis(AnalysisType.Apk, curl),
        makeAnalysis(AnalysisType.Apt, libc6),
      ],
      [apkAndDpkgLayer(curl, libc6)],
      ["sha256:a", "sha256:extra"],
    );

    expect(warnings).toHaveLength(2);
    expect(warnings.some((w) => w.includes("Apk"))).toBe(true);
    expect(warnings.some((w) => w.includes("Apt"))).toBe(true);
    for (const warning of warnings) {
      expect(warning).toMatch(/orderedLayers \(1\) and diffIDs \(2\)/);
    }
    expect(introducingLayerByPackage.size).toBe(0);
  });

  it("records cross-ecosystem key collisions and applies last-writer-wins", async () => {
    // With no source/origin, both PMs mint the bare key `curl@...`. The
    // collision must be surfaced (not silently dropped) and attribution must
    // still ship.
    const { introducingLayerByPackage, warnings } = await merge(
      [
        makeAnalysis(AnalysisType.Apk, curl),
        makeAnalysis(AnalysisType.Apt, curl),
      ],
      [apkAndDpkgLayer(curl, curl)],
      ["sha256:a"],
    );

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/curl@7\.0\.0-r0/);
    expect(warnings[0]).toMatch(/last-writer-wins/);
    expect(introducingLayerByPackage.get("curl@7.0.0-r0")).toBe("sha256:a");
  });
});
