import {
  checkHistoryAlignment,
  computeOsLayerAttribution,
  computeOsPackageManagerLayerAttribution,
} from "../../../lib/analyzer/layer-attribution";
import {
  AnalysisType,
  ImagePackagesAnalysis,
} from "../../../lib/analyzer/types";
import { ExtractedLayers } from "../../../lib/extractor/types";

// Minimal APK DB stanza format: "P:<name>\nV:<version>\n\n", with an
// optional `o:<origin>` field for the source/origin tests.
function makeApkDb(
  ...pkgs: Array<{ name: string; version: string; origin?: string }>
): string {
  return (
    pkgs
      .map((p) => {
        const lines = [`P:${p.name}`, `V:${p.version}`];
        if (p.origin) {
          lines.push(`o:${p.origin}`);
        }
        return lines.join("\n") + "\n";
      })
      .join("\n") + "\n"
  );
}

function makeApkLayer(content: string): ExtractedLayers {
  return {
    "/lib/apk/db/installed": { "apk-db": content },
  };
}

function makeAptLayer(dpkgContent: string): ExtractedLayers {
  return {
    "/var/lib/dpkg/status": { dpkg: dpkgContent },
  };
}

function makeDpkgStatus(
  ...pkgs: Array<{ name: string; version: string; source?: string }>
): string {
  return pkgs
    .map((p) => {
      const lines = [
        `Package: ${p.name}`,
        "Status: install ok installed",
        `Version: ${p.version}`,
      ];
      if (p.source) {
        // dpkg `Source` line lives between Status and Version in real
        // status files; order doesn't matter to the parser, but mirror
        // the typical layout for clarity.
        lines.splice(2, 0, `Source: ${p.source}`);
      }
      return lines.join("\n") + "\n";
    })
    .join("\n");
}

const emptyLayer: ExtractedLayers = {};
const image = "test-image:latest";

describe("checkHistoryAlignment", () => {
  // The backend performs the diffID -> instruction text join at read
  // time and is the authority on whether `rootfs.diff_ids[]` and
  // `history` align. The plugin only surfaces a user-visible warning when the OCI
  // rule "non-empty history entries map 1:1 to rootfs.diff_ids[]" does
  // not hold for this image. The per-package `dockerLayerDiffId` labels
  // are correct either way.

  it("returns no warning when non-empty history matches rootFs length", () => {
    expect(
      checkHistoryAlignment(
        ["sha256:a", "sha256:b"],
        [
          { created_by: "FROM alpine:3.19", empty_layer: false },
          { created_by: "RUN apk add curl", empty_layer: false },
        ],
      ),
    ).toBeUndefined();
  });

  it("ignores empty_layer entries when checking alignment", () => {
    expect(
      checkHistoryAlignment(
        ["sha256:a", "sha256:b"],
        [
          { created_by: "FROM alpine:3.19", empty_layer: false },
          { created_by: "ENV PATH=/bin", empty_layer: true },
          { created_by: "RUN apk add curl", empty_layer: false },
        ],
      ),
    ).toBeUndefined();
  });

  it("returns a warning when non-empty history is shorter than rootFs", () => {
    const warning = checkHistoryAlignment(
      ["sha256:a", "sha256:b", "sha256:c"],
      [
        { created_by: "FROM alpine:3.19", empty_layer: false },
        { created_by: "RUN apk add curl", empty_layer: false },
      ],
    );
    expect(warning).toBeDefined();
    expect(warning).toContain("does not align");
    expect(warning).toContain("history has 2");
    expect(warning).toContain("rootfs has 3");
  });

  it("treats null/undefined history as 'no history to align against' (no warning)", () => {
    // History being absent is a separate signal from misalignment —
    // there is simply nothing for the backend to join. The plugin must
    // not nag the user about a problem they cannot act on.
    expect(checkHistoryAlignment(["sha256:a"], null)).toBeUndefined();
    expect(checkHistoryAlignment(["sha256:a"], undefined)).toBeUndefined();
  });

  it("handles empty images", () => {
    expect(checkHistoryAlignment([], [])).toBeUndefined();
    expect(checkHistoryAlignment([], undefined)).toBeUndefined();
  });
});

describe("computeOsPackageManagerLayerAttribution", () => {
  describe("APK package manager", () => {
    it("attributes a single-layer image to layer 0", async () => {
      const orderedLayers = [
        makeApkLayer(
          makeApkDb(
            { name: "curl", version: "7.0.0-r0" },
            { name: "libc", version: "2.35-r1" },
          ),
        ),
      ];

      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:aaa"],
        image,
        undefined,
        [],
      );

      expect(result.get("curl@7.0.0-r0")).toBe("sha256:aaa");
      expect(result.get("libc@2.35-r1")).toBe("sha256:aaa");
    });

    it("attributes new packages to the layer that introduced them", async () => {
      const basePkgs = [
        { name: "libc", version: "2.35-r1" },
        { name: "curl", version: "7.0.0-r0" },
      ];
      const allPkgs = [...basePkgs, { name: "nginx", version: "1.24.0-r0" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(makeApkDb(...allPkgs)),
      ];
      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:base", "sha256:nginx-layer"],
        image,
        undefined,
        [],
      );

      expect(result.get("libc@2.35-r1")).toBe("sha256:base");
      expect(result.get("curl@7.0.0-r0")).toBe("sha256:base");
      expect(result.get("nginx@1.24.0-r0")).toBe("sha256:nginx-layer");
    });

    it("skips layers that do not write the package DB", async () => {
      const basePkgs = [{ name: "libc", version: "2.35-r1" }];
      const finalPkgs = [...basePkgs, { name: "nginx", version: "1.24.0-r0" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        emptyLayer, // COPY/ENV layer — no package DB
        makeApkLayer(makeApkDb(...finalPkgs)),
      ];
      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:a", "sha256:b", "sha256:c"],
        image,
        undefined,
        [],
      );

      expect(result.get("libc@2.35-r1")).toBe("sha256:a");
      expect(result.get("nginx@1.24.0-r0")).toBe("sha256:c");
    });

    it("distinguishes a missing DB file from an empty DB file", async () => {
      // emptyLayer (no DB at all) is a COPY/ENV layer — skipped, package
      // state unchanged. makeApkLayer("") (DB present but empty) means
      // every package was deleted in that layer, so previousPkgs must be
      // cleared, otherwise a later reinstall would not be re-attributed.
      const orderedLayers = [
        makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
        makeApkLayer(""), // all packages deleted
        makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
      ];

      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:a", "sha256:b", "sha256:c"],
        image,
        undefined,
        [],
      );

      // libc was wiped at layer b and reinstalled at layer c, so the
      // surviving copy is attributed to c, not a.
      expect(result.get("libc@2.35-r1")).toBe("sha256:c");
    });

    it("excludes packages that were removed and not reinstalled", async () => {
      // L0: install curl + libc; L1: remove curl. The surviving set is
      // {libc}; curl is gone from disk and so absent from the result.
      const orderedLayers = [
        makeApkLayer(
          makeApkDb(
            { name: "curl", version: "7.0.0-r0" },
            { name: "libc", version: "2.35-r1" },
          ),
        ),
        makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
      ];

      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:a", "sha256:b"],
        image,
        undefined,
        [],
      );

      expect(result.has("curl@7.0.0-r0")).toBe(false);
      expect(result.get("libc@2.35-r1")).toBe("sha256:a");
    });

    it("attributes a reinstalled package to its most recent install layer", async () => {
      // Same-version reinstall: only the latest copy is on disk in the
      // final image, and that's the layer the result must point at.
      const curl = { name: "curl", version: "7.0.0-r0" };
      const orderedLayers = [
        makeApkLayer(makeApkDb(curl)),
        makeApkLayer(""),
        makeApkLayer(makeApkDb(curl)),
        makeApkLayer(""),
        makeApkLayer(makeApkDb(curl)),
      ];

      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:l0", "sha256:l1", "sha256:l2", "sha256:l3", "sha256:l4"],
        image,
        undefined,
        [],
      );

      expect(result.get("curl@7.0.0-r0")).toBe("sha256:l4");
    });

    it("uses `<origin>/<binary>` keys when an apk Origin is present", async () => {
      // The label join the backend performs is keyed by `${depFullName}@${version}`.
      // An apk package `libcrypto3` with origin `openssl` must surface as
      // `openssl/libcrypto3@<ver>`, identical to the dep-graph node name
      // — otherwise the response-builder annotation step would miss every
      // openssl-style vuln.
      const orderedLayers = [
        makeApkLayer(
          makeApkDb({
            name: "libcrypto3",
            version: "3.0.7-r0",
            origin: "openssl",
          }),
        ),
      ];

      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:a"],
        image,
        undefined,
        [],
      );

      expect(result.get("openssl/libcrypto3@3.0.7-r0")).toBe("sha256:a");
      expect(result.has("libcrypto3@3.0.7-r0")).toBe(false);
    });

    it("returns an empty map when no layer has a package DB", async () => {
      const result = await computeOsPackageManagerLayerAttribution(
        [emptyLayer, emptyLayer],
        AnalysisType.Apk,
        ["sha256:a", "sha256:b"],
        image,
        undefined,
        [],
      );
      expect(result.size).toBe(0);
    });

    it("throws when orderedLayers and diffIDs lengths disagree", async () => {
      // Both arrays are produced by the extractor and describe the same
      // rootfs layers; a mismatch here is an internal invariant
      // violation, not a malformed-image case. Surface it loudly.
      const orderedLayers = [
        makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
        makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
      ];

      await expect(
        computeOsPackageManagerLayerAttribution(
          orderedLayers,
          AnalysisType.Apk,
          ["sha256:a"],
          image,
          undefined,
          [],
        ),
      ).rejects.toThrow(/orderedLayers \(2\) and diffIDs \(1\) must align/);
    });
  });

  describe("APT package manager", () => {
    it("attributes packages and uses `<source>/<binary>` keys when present", async () => {
      // glibc/libc-bin is the canonical case: the dep-graph node name
      // for the binary `libc-bin` is `glibc/libc-bin` (because the
      // Debian Source: header says `glibc`). The attribution map must
      // use the same shape so response-builder can annotate the node.
      const orderedLayers = [
        makeAptLayer(
          makeDpkgStatus({
            name: "libc-bin",
            version: "2.36-9+deb12u7",
            source: "glibc",
          }),
        ),
      ];

      const result = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        AnalysisType.Apt,
        ["sha256:a"],
        image,
        undefined,
        [],
      );

      expect(result.get("glibc/libc-bin@2.36-9+deb12u7")).toBe("sha256:a");
      expect(result.has("libc-bin@2.36-9+deb12u7")).toBe(false);
    });
  });
});

describe("computeOsLayerAttribution", () => {
  function makeAnalysis(
    analyzeType: Exclude<AnalysisType, AnalysisType.Binaries>,
    pkg: { name: string; version: string },
  ): ImagePackagesAnalysis {
    return {
      Image: image,
      AnalyzeType: analyzeType,
      Analysis: [
        {
          Name: pkg.name,
          Version: pkg.version,
          Provides: [],
          Deps: {},
        },
      ],
    };
  }

  it("dedupes by AnalyzeType so duplicate analyses don't double-count packages", async () => {
    // The top-level `Promise.all` in `static-analyzer.ts` produces
    // multiple `ImagePackagesAnalysis` records that share an
    // `AnalyzeType` whenever an image carries packages in more than
    // one DB format for the same ecosystem (RPM BDB/NDB + RPM SQLite,
    // regular APT + distroless APT). The orchestrator must call the
    // per-PM helper once per ecosystem; otherwise the second call's
    // result overwrites the first against an identical key, which is
    // a no-op — the *real* hazard is wasted work, but pin the contract.
    const orderedLayers = [
      makeApkLayer(makeApkDb({ name: "curl", version: "7.0.0-r0" })),
    ];
    const duplicateAnalyses: ImagePackagesAnalysis[] = [
      makeAnalysis(AnalysisType.Apk, { name: "curl", version: "7.0.0-r0" }),
      makeAnalysis(AnalysisType.Apk, { name: "curl", version: "7.0.0-r0" }),
    ];

    const onWarning = jest.fn();
    const result = await computeOsLayerAttribution(
      duplicateAnalyses,
      orderedLayers,
      ["sha256:a"],
      image,
      undefined,
      [],
      onWarning,
    );

    expect(result.get("curl@7.0.0-r0")).toBe("sha256:a");
    // Idempotent overwrite of the same key/value should not fire a
    // collision warning when the diffID is identical (we still call
    // .set() but the post-call value matches the pre-call value, so we
    // accept either zero or one warning — the contract is "no
    // duplicate ecosystem call", not "no warning").
    // Note: the helper dedupes via Set<AnalyzeType>, so this is also
    // a regression test against re-introducing per-result iteration.
    expect(onWarning).not.toHaveBeenCalled();
  });

  it("merges results across ecosystems on a mixed image", async () => {
    // Mixed apk + dpkg images are uncommon but valid; the orchestrator
    // must run attribution for each ecosystem and merge the maps.
    const orderedLayers: ExtractedLayers[] = [
      {
        "/lib/apk/db/installed": {
          "apk-db": makeApkDb({ name: "curl", version: "7.0.0-r0" }),
        },
        "/var/lib/dpkg/status": {
          dpkg: makeDpkgStatus({ name: "libc6", version: "2.35-0ubuntu3" }),
        },
      },
    ];
    const analyses: ImagePackagesAnalysis[] = [
      makeAnalysis(AnalysisType.Apk, { name: "curl", version: "7.0.0-r0" }),
      makeAnalysis(AnalysisType.Apt, {
        name: "libc6",
        version: "2.35-0ubuntu3",
      }),
    ];

    const result = await computeOsLayerAttribution(
      analyses,
      orderedLayers,
      ["sha256:a"],
      image,
      undefined,
      [],
    );

    expect(result.get("curl@7.0.0-r0")).toBe("sha256:a");
    expect(result.get("libc6@2.35-0ubuntu3")).toBe("sha256:a");
  });

  it("filters out empty Analysis entries before invoking attribution", async () => {
    // An empty `Analysis` means the ecosystem's top-level parse found
    // nothing; doing a per-layer pass for it is wasted work.
    const orderedLayers = [
      makeApkLayer(makeApkDb({ name: "curl", version: "7.0.0-r0" })),
    ];
    const analyses: ImagePackagesAnalysis[] = [
      makeAnalysis(AnalysisType.Apk, { name: "curl", version: "7.0.0-r0" }),
      { Image: image, AnalyzeType: AnalysisType.Rpm, Analysis: [] },
    ];

    const result = await computeOsLayerAttribution(
      analyses,
      orderedLayers,
      ["sha256:a"],
      image,
      undefined,
      [],
    );

    expect(result.size).toBe(1);
    expect(result.get("curl@7.0.0-r0")).toBe("sha256:a");
  });

  it("returns an empty map when there are no analyses", async () => {
    const result = await computeOsLayerAttribution(
      [],
      [makeApkLayer(makeApkDb({ name: "curl", version: "7.0.0-r0" }))],
      ["sha256:a"],
      image,
      undefined,
      [],
    );
    expect(result.size).toBe(0);
  });

  it("reports per-ecosystem failures via onWarning instead of throwing", async () => {
    // A length mismatch between orderedLayers and diffIDs is the
    // easiest deterministic way to make the per-PM helper throw; the
    // helper shares one metadata object across all per-ecosystem
    // calls, so a mismatch causes every per-PM call to fail.
    const orderedLayers: ExtractedLayers[] = [
      {
        "/lib/apk/db/installed": {
          "apk-db": makeApkDb({ name: "curl", version: "7.0.0-r0" }),
        },
        "/var/lib/dpkg/status": {
          dpkg: makeDpkgStatus({ name: "libc6", version: "2.35-0ubuntu3" }),
        },
      },
    ];
    const analyses: ImagePackagesAnalysis[] = [
      makeAnalysis(AnalysisType.Apk, { name: "curl", version: "7.0.0-r0" }),
      makeAnalysis(AnalysisType.Apt, {
        name: "libc6",
        version: "2.35-0ubuntu3",
      }),
    ];
    const warnings: Array<{ type: AnalysisType; warning: Error }> = [];

    const result = await computeOsLayerAttribution(
      analyses,
      orderedLayers,
      // diffIDs.length !== orderedLayers.length → both per-PM calls throw.
      ["sha256:a", "sha256:extra"],
      image,
      undefined,
      [],
      (type, warning) => warnings.push({ type, warning }),
    );

    expect(warnings.map((w) => w.type).sort()).toEqual([
      AnalysisType.Apk,
      AnalysisType.Apt,
    ]);
    for (const { warning } of warnings) {
      expect(warning).toBeInstanceOf(Error);
      expect(warning.message).toMatch(/orderedLayers \(1\) and diffIDs \(2\)/);
    }
    expect(result.size).toBe(0);
  });

  it("reports cross-ecosystem key collisions via onWarning and applies last-writer-wins", async () => {
    // Each OS PM is expected to occupy a disjoint `<source>/<binary>`
    // namespace; a collision indicates either a bug in our key shape or
    // an exotic image. We don't want the second writer silently
    // overwriting — the helper must surface the collision but keep
    // going so the rest of attribution still ships.
    //
    // Force the collision: a single layer with both an apk DB and a
    // dpkg status file, each carrying `curl 7.0.0-r0` with no
    // source/origin. `depFullName` falls back to `<name>` when no
    // source is recorded, so both PMs produce the key `curl@7.0.0-r0`.
    const orderedLayers: ExtractedLayers[] = [
      {
        "/lib/apk/db/installed": {
          "apk-db": makeApkDb({ name: "curl", version: "7.0.0-r0" }),
        },
        "/var/lib/dpkg/status": {
          dpkg: makeDpkgStatus({ name: "curl", version: "7.0.0-r0" }),
        },
      },
    ];
    const analyses: ImagePackagesAnalysis[] = [
      makeAnalysis(AnalysisType.Apk, { name: "curl", version: "7.0.0-r0" }),
      makeAnalysis(AnalysisType.Apt, { name: "curl", version: "7.0.0-r0" }),
    ];
    const warnings: Array<{ type: AnalysisType; warning: Error }> = [];

    const result = await computeOsLayerAttribution(
      analyses,
      orderedLayers,
      ["sha256:a"],
      image,
      undefined,
      [],
      (type, warning) => warnings.push({ type, warning }),
    );

    expect(warnings).toHaveLength(1);
    expect(warnings[0].warning.message).toMatch(/curl@7\.0\.0-r0/);
    expect(warnings[0].warning.message).toMatch(/last-writer-wins/);
    // Attribution still shipped: the surviving entry maps to the one
    // layer that introduced the package.
    expect(result.get("curl@7.0.0-r0")).toBe("sha256:a");
  });
});
