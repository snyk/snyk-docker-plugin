import {
  alignLayerMetadata,
  computeLayerAttribution,
  mergeLayerAttributionEntries,
} from "../../../lib/analyzer/layer-attribution";
import { AnalysisType } from "../../../lib/analyzer/types";
import { ExtractedLayers } from "../../../lib/extractor/types";
import { LayerAttributionEntry } from "../../../lib/facts";

// Minimal APK DB stanza format: "P:<name>\nV:<version>\n\n"
function makeApkDb(...pkgs: Array<{ name: string; version: string }>): string {
  return pkgs.map((p) => `P:${p.name}\nV:${p.version}\n`).join("\n") + "\n";
}

function makeApkLayer(content: string): ExtractedLayers {
  return {
    "/lib/apk/db/installed": { "apk-db": content },
  };
}

const emptyLayer: ExtractedLayers = {};

describe("computeLayerAttribution", () => {
  const image = "test-image:latest";

  describe("APK package manager", () => {
    it("attributes all packages to layer 0 when there is only one layer", async () => {
      const pkgs = [
        { name: "curl", version: "7.0.0-r0" },
        { name: "libc", version: "2.35-r1" },
      ];
      const orderedLayers = [makeApkLayer(makeApkDb(...pkgs))];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        {
          diffIDs: ["sha256:aaa"],
          manifestDigests: ["sha256:aaa-compressed"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[0].diffID).toBe("sha256:aaa");
      expect(result.entries[0].digest).toBe("sha256:aaa-compressed");
      expect(result.entries[0].packages).toContain("curl@7.0.0-r0");
      expect(result.entries[0].packages).toContain("libc@2.35-r1");

      expect(result.finalImagePackages.get("curl@7.0.0-r0")).toEqual([
        { layerIndex: 0, diffID: "sha256:aaa" },
      ]);
    });

    it("attributes new packages to the layer where they first appear", async () => {
      const basePkgs = [
        { name: "libc", version: "2.35-r1" },
        { name: "curl", version: "7.0.0-r0" },
      ];
      const allPkgs = [...basePkgs, { name: "nginx", version: "1.24.0-r0" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(makeApkDb(...allPkgs)),
      ];
      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        {
          diffIDs: ["sha256:base", "sha256:nginx-layer"],
          manifestDigests: ["sha256:base-c", "sha256:nginx-c"],
          instructions: ["FROM alpine:3.19", "RUN apk add nginx"],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);

      const layer0 = result.entries[0];
      expect(layer0.layerIndex).toBe(0);
      expect(layer0.diffID).toBe("sha256:base");
      expect(layer0.instruction).toBe("FROM alpine:3.19");
      expect(layer0.packages).toContain("libc@2.35-r1");
      expect(layer0.packages).toContain("curl@7.0.0-r0");
      expect(layer0.packages).not.toContain("nginx@1.24.0-r0");

      const layer1 = result.entries[1];
      expect(layer1.layerIndex).toBe(1);
      expect(layer1.diffID).toBe("sha256:nginx-layer");
      expect(layer1.instruction).toBe("RUN apk add nginx");
      expect(layer1.packages).toEqual(["nginx@1.24.0-r0"]);

      expect(result.finalImagePackages.get("nginx@1.24.0-r0")).toEqual([
        { layerIndex: 1, diffID: "sha256:nginx-layer" },
      ]);
    });

    it("skips layers that do not write the package DB", async () => {
      const basePkgs = [{ name: "libc", version: "2.35-r1" }];
      const finalPkgs = [...basePkgs, { name: "nginx", version: "1.24.0-r0" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        emptyLayer, // COPY or ENV instruction — no package DB
        makeApkLayer(makeApkDb(...finalPkgs)),
      ];
      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        {
          diffIDs: ["sha256:a", "sha256:b", "sha256:c"],
          manifestDigests: ["sha256:a", "sha256:b", "sha256:c"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[1].layerIndex).toBe(2);
      expect(result.entries[1].packages).toEqual(["nginx@1.24.0-r0"]);
    });

    it("distinguishes a missing DB file from an empty DB file", async () => {
      // `emptyLayer` (no DB file at all) is a COPY/ENV layer — skipped entirely.
      // `makeApkLayer("")` (DB file present but empty) means all packages were
      // explicitly removed (e.g. `apk del $(apk info)`). The empty DB must be
      // parsed so that previousPkgs gets cleared, otherwise a later reinstall
      // would not be re-attributed correctly.
      const basePkgs = [{ name: "libc", version: "2.35-r1" }];
      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(""), // APK DB file exists but is empty — all packages deleted
      ];
      const diffIDs = ["sha256:a", "sha256:b"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        { diffIDs, manifestDigests: diffIDs, instructions: [] },
        image,
        undefined,
        [],
      );

      // Layer 0 introduces libc; layer 1 has no additions, so no entry.
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[0].packages).toContain("libc@2.35-r1");
    });

    it("does not emit an entry for a layer that only deletes packages", async () => {
      // Layer 0: base image with curl + libc
      // Layer 1: curl deleted (apk del curl) — DB rewritten without it
      // Expected: curl attributed to layer 0; layer 1 has no additions, so no
      // entry. Removals are intentionally not surfaced in the output.
      const basePkgs = [
        { name: "curl", version: "7.0.0-r0" },
        { name: "libc", version: "2.35-r1" },
      ];
      const afterDeletionPkgs = [{ name: "libc", version: "2.35-r1" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(makeApkDb(...afterDeletionPkgs)),
      ];
      const diffIDs = ["sha256:base", "sha256:del-curl"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        { diffIDs, manifestDigests: diffIDs, instructions: [] },
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[0].packages).toContain("curl@7.0.0-r0");
      expect(result.entries[0].packages).toContain("libc@2.35-r1");

      // libc remains in finalImagePackages (live); curl was removed and
      // is no longer in the live set, even though entries[L0] still
      // recorded its introduction.
      expect(result.finalImagePackages.has("curl@7.0.0-r0")).toBe(false);
      expect(result.finalImagePackages.get("libc@2.35-r1")).toEqual([
        { layerIndex: 0, diffID: "sha256:base" },
      ]);
    });

    it("re-attributes a package reinstalled after deletion", async () => {
      // Layer 0: curl@7.0 + libc
      // Layer 1: curl deleted — no entry (removals are not surfaced)
      // Layer 2: curl@8.0 reinstalled → packages: [curl@8.0]
      const basePkgs = [
        { name: "curl", version: "7.0.0-r0" },
        { name: "libc", version: "2.35-r1" },
      ];
      const afterDeletionPkgs = [{ name: "libc", version: "2.35-r1" }];
      const afterReinstallPkgs = [
        { name: "libc", version: "2.35-r1" },
        { name: "curl", version: "8.0.0-r0" },
      ];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(makeApkDb(...afterDeletionPkgs)),
        makeApkLayer(makeApkDb(...afterReinstallPkgs)),
      ];
      const diffIDs = ["sha256:base", "sha256:del", "sha256:reinstall"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        { diffIDs, manifestDigests: diffIDs, instructions: [] },
        image,
        undefined,
        [],
      );

      // Two entries: base install (layer 0) and reinstall (layer 2). Layer 1
      // performs only a deletion and so produces no entry.
      expect(result.entries).toHaveLength(2);

      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[0].packages).toContain("curl@7.0.0-r0");
      expect(result.entries[0].packages).toContain("libc@2.35-r1");

      expect(result.entries[1].layerIndex).toBe(2);
      expect(result.entries[1].packages).toEqual(["curl@8.0.0-r0"]);

      // curl@8 is in the final image, attributed to its install layer.
      expect(result.finalImagePackages.get("curl@8.0.0-r0")).toEqual([
        { layerIndex: 2, diffID: "sha256:reinstall" },
      ]);
      // curl@7 was removed and never reinstalled at that version, so it's
      // visible in entries[L0] (shadow-vuln candidate) but absent from
      // the live set.
      expect(result.finalImagePackages.has("curl@7.0.0-r0")).toBe(false);
    });

    describe("finalImagePackages live-set indexing", () => {
      // The producer emits the raw introduction stream in `entries[]` and a
      // separate `finalImagePackages` map of "what's on disk in the final
      // image, and where it came from." These tests pin the contract that
      // entries are NOT filtered by survivor status (so shadow / audit
      // consumers can see history) while finalImagePackages reflects only
      // the live set.

      it("keeps both entries on same-version reinstall but only points finalImagePackages at the latest", async () => {
        // L0: curl@7 + libc
        // L1: curl deleted (DB rewritten without it)
        // L2: curl@7 reinstalled at the SAME version
        //
        // The L0 copy of curl@7 was wiped at L1; only the L2 copy exists
        // on disk. Both introductions remain visible in `entries[]`;
        // `finalImagePackages` points only at the surviving L2 origin.
        const basePkgs = [
          { name: "curl", version: "7.0.0-r0" },
          { name: "libc", version: "2.35-r1" },
        ];
        const afterDeletionPkgs = [{ name: "libc", version: "2.35-r1" }];
        const afterReinstallPkgs = [
          { name: "libc", version: "2.35-r1" },
          { name: "curl", version: "7.0.0-r0" },
        ];

        const orderedLayers = [
          makeApkLayer(makeApkDb(...basePkgs)),
          makeApkLayer(makeApkDb(...afterDeletionPkgs)),
          makeApkLayer(makeApkDb(...afterReinstallPkgs)),
        ];
        const diffIDs = ["sha256:base", "sha256:del", "sha256:reinstall"];

        const result = await computeLayerAttribution(
          orderedLayers,
          AnalysisType.Apk,
          { diffIDs, manifestDigests: diffIDs, instructions: [] },
          image,
          undefined,
          [],
        );

        // entries[]: both introductions of curl@7 are preserved.
        expect(result.entries).toHaveLength(2);
        const layer0 = result.entries.find((e) => e.layerIndex === 0)!;
        expect(layer0.packages).toEqual(
          expect.arrayContaining(["curl@7.0.0-r0", "libc@2.35-r1"]),
        );
        const layer2 = result.entries.find((e) => e.layerIndex === 2)!;
        expect(layer2.packages).toEqual(["curl@7.0.0-r0"]);

        // finalImagePackages: only the surviving L2 origin for curl@7.
        expect(result.finalImagePackages.get("curl@7.0.0-r0")).toEqual([
          { layerIndex: 2, diffID: "sha256:reinstall" },
        ]);
        expect(result.finalImagePackages.get("libc@2.35-r1")).toEqual([
          { layerIndex: 0, diffID: "sha256:base" },
        ]);
      });

      it("traces the latest live origin across multiple install/remove cycles", async () => {
        // L0: install curl@7
        // L1: remove curl
        // L2: install curl@7 (first reinstall)
        // L3: remove curl
        // L4: install curl@7 (second reinstall)
        //
        // entries[] should record all three introductions; finalImagePackages
        // points only at L4 because that's the only copy still on disk.
        const curl = { name: "curl", version: "7.0.0-r0" };
        const orderedLayers = [
          makeApkLayer(makeApkDb(curl)),
          makeApkLayer(""),
          makeApkLayer(makeApkDb(curl)),
          makeApkLayer(""),
          makeApkLayer(makeApkDb(curl)),
        ];
        const diffIDs = [
          "sha256:l0",
          "sha256:l1",
          "sha256:l2",
          "sha256:l3",
          "sha256:l4",
        ];

        const result = await computeLayerAttribution(
          orderedLayers,
          AnalysisType.Apk,
          { diffIDs, manifestDigests: diffIDs, instructions: [] },
          image,
          undefined,
          [],
        );

        const introducingLayers = result.entries
          .filter((e) => e.packages.includes("curl@7.0.0-r0"))
          .map((e) => e.layerIndex);
        expect(introducingLayers).toEqual([0, 2, 4]);

        expect(result.finalImagePackages.get("curl@7.0.0-r0")).toEqual([
          { layerIndex: 4, diffID: "sha256:l4" },
        ]);
      });

      it("omits packages from finalImagePackages when they were removed and not reinstalled", async () => {
        // L0: install curl@7 + libc
        // L1: remove curl (libc remains)
        //
        // curl@7 is in entries[L0] (audit / shadow-vuln visible) but NOT in
        // finalImagePackages (it's gone). libc is in both.
        const orderedLayers = [
          makeApkLayer(
            makeApkDb(
              { name: "curl", version: "7.0.0-r0" },
              { name: "libc", version: "2.35-r1" },
            ),
          ),
          makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
        ];
        const diffIDs = ["sha256:base", "sha256:del"];

        const result = await computeLayerAttribution(
          orderedLayers,
          AnalysisType.Apk,
          { diffIDs, manifestDigests: diffIDs, instructions: [] },
          image,
          undefined,
          [],
        );

        const layer0 = result.entries.find((e) => e.layerIndex === 0)!;
        expect(layer0.packages).toEqual(
          expect.arrayContaining(["curl@7.0.0-r0", "libc@2.35-r1"]),
        );

        expect(result.finalImagePackages.has("curl@7.0.0-r0")).toBe(false);
        expect(result.finalImagePackages.get("libc@2.35-r1")).toEqual([
          { layerIndex: 0, diffID: "sha256:base" },
        ]);
      });

      it("represents version upgrades as two distinct keys with only the upgraded one live", async () => {
        // L0: curl@7 + libc
        // L1: only libc (curl@7 removed)
        // L2: libc + curl@8
        //
        // curl@7 lives only in entries (shadow-vuln candidate); curl@8 lives
        // in both. This is the canonical "vuln introduced at L0, remediated
        // by upgrade at L2" pattern that the dual-output shape was designed
        // to support without a dedicated `removedPackages` field.
        const orderedLayers = [
          makeApkLayer(
            makeApkDb(
              { name: "curl", version: "7.0.0-r0" },
              { name: "libc", version: "2.35-r1" },
            ),
          ),
          makeApkLayer(makeApkDb({ name: "libc", version: "2.35-r1" })),
          makeApkLayer(
            makeApkDb(
              { name: "libc", version: "2.35-r1" },
              { name: "curl", version: "8.0.0-r0" },
            ),
          ),
        ];
        const diffIDs = ["sha256:base", "sha256:del", "sha256:up"];

        const result = await computeLayerAttribution(
          orderedLayers,
          AnalysisType.Apk,
          { diffIDs, manifestDigests: diffIDs, instructions: [] },
          image,
          undefined,
          [],
        );

        const layer0 = result.entries.find((e) => e.layerIndex === 0)!;
        expect(layer0.packages).toEqual(
          expect.arrayContaining(["curl@7.0.0-r0", "libc@2.35-r1"]),
        );

        const layer2 = result.entries.find((e) => e.layerIndex === 2)!;
        expect(layer2.packages).toEqual(["curl@8.0.0-r0"]);

        expect(result.finalImagePackages.has("curl@7.0.0-r0")).toBe(false);
        expect(result.finalImagePackages.get("curl@8.0.0-r0")).toEqual([
          { layerIndex: 2, diffID: "sha256:up" },
        ]);
        expect(result.finalImagePackages.get("libc@2.35-r1")).toEqual([
          { layerIndex: 0, diffID: "sha256:base" },
        ]);
      });
    });

    it("returns empty entries when no layer has a package DB", async () => {
      const result = await computeLayerAttribution(
        [emptyLayer, emptyLayer],
        AnalysisType.Apk,
        {
          diffIDs: ["sha256:a", "sha256:b"],
          manifestDigests: ["sha256:a", "sha256:b"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(0);
      expect(result.finalImagePackages.size).toBe(0);
    });

    it("throws when orderedLayers and diffIDs have mismatched lengths", async () => {
      // A length mismatch between orderedLayers (extractor file contents) and
      // diffIDs (extractor's rootfs.diff_ids view of the same layers) is an
      // internal invariant violation — we want it to surface loudly rather
      // than silently truncate and produce confidently-wrong attribution.
      const pkgs = [{ name: "libc", version: "2.35-r1" }];
      const orderedLayers = [
        makeApkLayer(makeApkDb(...pkgs)),
        makeApkLayer(makeApkDb(...pkgs, { name: "extra", version: "1.0-r0" })),
      ];
      const diffIDs = ["sha256:a"];

      await expect(
        computeLayerAttribution(
          orderedLayers,
          AnalysisType.Apk,
          { diffIDs, manifestDigests: diffIDs, instructions: [] },
          image,
          undefined,
          [],
        ),
      ).rejects.toThrow(/orderedLayers \(2\) and diffIDs \(1\) must align/);
    });

    it("omits instruction when no instruction is supplied for that layer", async () => {
      const orderedLayers = [
        makeApkLayer(makeApkDb({ name: "curl", version: "7.0.0-r0" })),
      ];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        {
          diffIDs: ["sha256:aaa"],
          manifestDigests: ["sha256:aaa"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries[0].instruction).toBeUndefined();
    });
  });

  describe("APT package manager", () => {
    function makeAptLayer(dpkgContent: string): ExtractedLayers {
      return {
        "/var/lib/dpkg/status": { dpkg: dpkgContent },
      };
    }

    function makeDpkgStatus(
      ...pkgs: Array<{ name: string; version: string }>
    ): string {
      return pkgs
        .map(
          (p) =>
            `Package: ${p.name}\nStatus: install ok installed\nVersion: ${p.version}\n`,
        )
        .join("\n");
    }

    it("attributes packages to layers for APT package manager", async () => {
      const basePkgs = [{ name: "libc6", version: "2.35-0ubuntu3" }];
      const allPkgs = [
        ...basePkgs,
        { name: "nginx", version: "1.18.0-6ubuntu14" },
      ];

      const orderedLayers = [
        makeAptLayer(makeDpkgStatus(...basePkgs)),
        makeAptLayer(makeDpkgStatus(...allPkgs)),
      ];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apt,
        {
          diffIDs: ["sha256:base", "sha256:nginx-layer"],
          manifestDigests: ["sha256:base", "sha256:nginx-layer"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].packages).toContain("libc6@2.35-0ubuntu3");
      expect(result.entries[1].packages).toContain("nginx@1.18.0-6ubuntu14");
    });

    it("uses `<source>/<binary>` keys when a Source is present (apt)", async () => {
      // Pins the load-bearing join shape: a Debian binary like `libc-bin`
      // whose source package is `glibc` must surface in the fact as
      // `glibc/libc-bin@<ver>`, identical to the dep-graph node name (and
      // therefore identical to the leaf of a vuln's `from[]`). Without
      // this, a downstream consumer matching `vuln.packageName ->
      // finalImagePackages[...]` would miss every glibc-style vuln —
      // i.e. the bulk of OS CVEs (libc, openssl, pam, systemd, ...).
      const dpkgWithSource =
        "Package: libc-bin\n" +
        "Status: install ok installed\n" +
        "Source: glibc\n" +
        "Version: 2.36-9+deb12u7\n";

      const orderedLayers = [makeAptLayer(dpkgWithSource)];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apt,
        {
          diffIDs: ["sha256:a"],
          manifestDigests: ["sha256:a"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries[0].packages).toContain(
        "glibc/libc-bin@2.36-9+deb12u7",
      );
      expect(result.entries[0].packages).not.toContain(
        "libc-bin@2.36-9+deb12u7",
      );
      expect(
        result.finalImagePackages.get("glibc/libc-bin@2.36-9+deb12u7"),
      ).toEqual([{ layerIndex: 0, diffID: "sha256:a" }]);
    });
  });

  describe("APK package manager — origin handling", () => {
    // APK encodes the source/origin as the `o:` field. Mirrors the apt
    // case above: `libcrypto3` has origin `openssl` and so must surface
    // as `openssl/libcrypto3@<ver>` in the fact, joining 1:1 with the
    // dep-graph node name and any vuln's `packageName`.
    function makeApkLayerWithOrigin(
      ...pkgs: Array<{ name: string; version: string; origin?: string }>
    ): ExtractedLayers {
      const stanza = (p: {
        name: string;
        version: string;
        origin?: string;
      }) => {
        const lines = [`P:${p.name}`, `V:${p.version}`];
        if (p.origin) {
          lines.push(`o:${p.origin}`);
        }
        return lines.join("\n") + "\n";
      };
      return {
        "/lib/apk/db/installed": {
          "apk-db": pkgs.map(stanza).join("\n") + "\n",
        },
      };
    }

    it("uses `<origin>/<binary>` keys when an apk Origin is present", async () => {
      const orderedLayers = [
        makeApkLayerWithOrigin({
          name: "libcrypto3",
          version: "3.0.7-r0",
          origin: "openssl",
        }),
      ];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        {
          diffIDs: ["sha256:a"],
          manifestDigests: ["sha256:a"],
          instructions: [],
        },
        image,
        undefined,
        [],
      );

      expect(result.entries[0].packages).toContain(
        "openssl/libcrypto3@3.0.7-r0",
      );
      expect(
        result.finalImagePackages.get("openssl/libcrypto3@3.0.7-r0"),
      ).toEqual([{ layerIndex: 0, diffID: "sha256:a" }]);
    });
  });
});

describe("alignLayerMetadata", () => {
  it("returns aligned arrays when both manifestLayers and history match rootFsLayers length", () => {
    const result = alignLayerMetadata(
      ["sha256:a", "sha256:b"],
      ["sha256:a-c", "sha256:b-c"],
      [
        { created_by: "FROM alpine:3.19", empty_layer: false },
        { created_by: "RUN apk add curl", empty_layer: false },
      ],
    );
    expect(result.diffIDs).toEqual(["sha256:a", "sha256:b"]);
    expect(result.manifestDigests).toEqual(["sha256:a-c", "sha256:b-c"]);
    expect(result.instructions).toEqual([
      "FROM alpine:3.19",
      "RUN apk add curl",
    ]);
  });

  it("filters out empty_layer history entries before length comparison", () => {
    const result = alignLayerMetadata(
      ["sha256:a", "sha256:b"],
      ["sha256:a", "sha256:b"],
      [
        { created_by: "FROM alpine:3.19", empty_layer: false },
        { created_by: "ENV PATH=/bin", empty_layer: true },
        { created_by: "RUN apk add curl", empty_layer: false },
      ],
    );
    expect(result.instructions).toEqual([
      "FROM alpine:3.19",
      "RUN apk add curl",
    ]);
  });

  it("returns empty instructions when filtered history length does not match rootFsLayers", () => {
    const result = alignLayerMetadata(
      ["sha256:a", "sha256:b", "sha256:c"],
      ["sha256:a", "sha256:b", "sha256:c"],
      [
        { created_by: "FROM alpine:3.19", empty_layer: false },
        { created_by: "RUN apk add curl", empty_layer: false },
      ],
    );
    expect(result.instructions).toEqual([]);
    expect(result.manifestDigests).toEqual([
      "sha256:a",
      "sha256:b",
      "sha256:c",
    ]);
  });

  it("returns empty manifestDigests when manifestLayers length does not match rootFsLayers", () => {
    const result = alignLayerMetadata(
      ["sha256:a", "sha256:b"],
      ["sha256:a"],
      null,
    );
    expect(result.manifestDigests).toEqual([]);
    expect(result.instructions).toEqual([]);
  });

  it("returns empty instructions when history is null or undefined", () => {
    const fromNull = alignLayerMetadata(["sha256:a"], ["sha256:a"], null);
    const fromUndef = alignLayerMetadata(["sha256:a"], ["sha256:a"], undefined);
    expect(fromNull.instructions).toEqual([]);
    expect(fromUndef.instructions).toEqual([]);
  });
});

describe("mergeLayerAttributionEntries", () => {
  it("returns an empty array for no entries", () => {
    expect(mergeLayerAttributionEntries([])).toEqual([]);
  });

  it("returns a single entry unchanged", () => {
    const entry: LayerAttributionEntry = {
      layerIndex: 0,
      diffID: "sha256:aaa",
      digest: "sha256:aaa-c",
      instruction: "FROM alpine:3.19",
      packages: ["libc@2.35-r1"],
    };
    const result = mergeLayerAttributionEntries([entry]);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(entry);
  });

  it("sorts entries by layerIndex", () => {
    const entries: LayerAttributionEntry[] = [
      { layerIndex: 2, diffID: "sha256:c", packages: ["c@1.0"] },
      { layerIndex: 0, diffID: "sha256:a", packages: ["a@1.0"] },
      { layerIndex: 1, diffID: "sha256:b", packages: ["b@1.0"] },
    ];
    const result = mergeLayerAttributionEntries(entries);
    expect(result.map((e) => e.layerIndex)).toEqual([0, 1, 2]);
  });

  it("merges packages from two managers into the same layer entry", () => {
    const entries: LayerAttributionEntry[] = [
      { layerIndex: 0, diffID: "sha256:a", packages: ["apt-pkg@1.0"] },
      { layerIndex: 0, diffID: "sha256:a", packages: ["chisel-pkg@2.0"] },
    ];
    const result = mergeLayerAttributionEntries(entries);
    expect(result).toHaveLength(1);
    expect(result[0].packages).toContain("apt-pkg@1.0");
    expect(result[0].packages).toContain("chisel-pkg@2.0");
  });

  it("preserves layer metadata (diffID, digest, instruction) from the first entry", () => {
    const entries: LayerAttributionEntry[] = [
      {
        layerIndex: 0,
        diffID: "sha256:aaa",
        digest: "sha256:aaa-compressed",
        instruction: "FROM ubuntu:22.04",
        packages: ["libc6@2.35"],
      },
      { layerIndex: 0, diffID: "sha256:aaa", packages: ["chisel-pkg@1.0"] },
    ];
    const result = mergeLayerAttributionEntries(entries);
    expect(result[0].digest).toBe("sha256:aaa-compressed");
    expect(result[0].instruction).toBe("FROM ubuntu:22.04");
  });

  it("keeps entries for different layers independent", () => {
    const entries: LayerAttributionEntry[] = [
      { layerIndex: 0, diffID: "sha256:a", packages: ["a@1.0"] },
      { layerIndex: 1, diffID: "sha256:b", packages: ["b@1.0"] },
      { layerIndex: 0, diffID: "sha256:a", packages: ["c@1.0"] },
    ];
    const result = mergeLayerAttributionEntries(entries);
    expect(result).toHaveLength(2);
    expect(result[0].layerIndex).toBe(0);
    expect(result[0].packages).toEqual(
      expect.arrayContaining(["a@1.0", "c@1.0"]),
    );
    expect(result[1].layerIndex).toBe(1);
    expect(result[1].packages).toEqual(["b@1.0"]);
  });
});
