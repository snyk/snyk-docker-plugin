import {
  computeLayerAttribution,
  LayerAttributionResult,
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
      const rootFsLayers = ["sha256:aaa"];
      const manifestLayers = ["sha256:aaa-compressed"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        null,
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

      expect(result.pkgLayerMap.get("curl@7.0.0-r0")).toEqual({
        layerIndex: 0,
        diffID: "sha256:aaa",
      });
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
      const rootFsLayers = ["sha256:base", "sha256:nginx-layer"];
      const manifestLayers = ["sha256:base-c", "sha256:nginx-c"];
      const history = [
        { created_by: "FROM alpine:3.19", empty_layer: false },
        { created_by: "RUN apk add nginx", empty_layer: false },
      ];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        history,
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

      expect(result.pkgLayerMap.get("nginx@1.24.0-r0")).toEqual({
        layerIndex: 1,
        diffID: "sha256:nginx-layer",
      });
    });

    it("skips layers that do not write the package DB", async () => {
      const basePkgs = [{ name: "libc", version: "2.35-r1" }];
      const finalPkgs = [...basePkgs, { name: "nginx", version: "1.24.0-r0" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        emptyLayer, // COPY or ENV instruction — no package DB
        makeApkLayer(makeApkDb(...finalPkgs)),
      ];
      const rootFsLayers = ["sha256:a", "sha256:b", "sha256:c"];
      const manifestLayers = ["sha256:a", "sha256:b", "sha256:c"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[1].layerIndex).toBe(2);
      expect(result.entries[1].packages).toEqual(["nginx@1.24.0-r0"]);
    });

    it("treats a layer with an empty DB file as clearing all packages", async () => {
      // `emptyLayer` (no DB file at all) is a COPY/ENV layer — skipped entirely.
      // `makeApkLayer("")` (DB file present but empty) means all packages were
      // explicitly removed (e.g. `apk del $(apk info)`). It must be tracked.
      const basePkgs = [{ name: "libc", version: "2.35-r1" }];
      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(""), // APK DB file exists but is empty — all packages deleted
      ];
      const rootFsLayers = ["sha256:a", "sha256:b"];
      const manifestLayers = rootFsLayers;

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].packages).toContain("libc@2.35-r1");
      expect(result.entries[1].packages).toHaveLength(0);
      expect(result.entries[1].removedPackages).toEqual(["libc@2.35-r1"]);
    });

    it("records a deletion in the layer where the package disappears", async () => {
      // Layer 0: base image with curl + libc
      // Layer 1: curl deleted (apk del curl) — DB rewritten without it
      // Expected: curl attributed to layer 0; layer 1 has no new packages but
      // records curl in removedPackages
      const basePkgs = [
        { name: "curl", version: "7.0.0-r0" },
        { name: "libc", version: "2.35-r1" },
      ];
      const afterDeletionPkgs = [{ name: "libc", version: "2.35-r1" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(makeApkDb(...afterDeletionPkgs)),
      ];
      const rootFsLayers = ["sha256:base", "sha256:del-curl"];
      const manifestLayers = ["sha256:base", "sha256:del-curl"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);

      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[0].packages).toContain("curl@7.0.0-r0");
      expect(result.entries[0].packages).toContain("libc@2.35-r1");
      expect(result.entries[0].removedPackages).toBeUndefined();

      expect(result.entries[1].layerIndex).toBe(1);
      expect(result.entries[1].packages).toHaveLength(0);
      expect(result.entries[1].removedPackages).toEqual(["curl@7.0.0-r0"]);

      // pkgLayerMap still records original attribution for both packages
      expect(result.pkgLayerMap.get("curl@7.0.0-r0")).toEqual({
        layerIndex: 0,
        diffID: "sha256:base",
      });
      expect(result.pkgLayerMap.get("libc@2.35-r1")).toEqual({
        layerIndex: 0,
        diffID: "sha256:base",
      });
    });

    it("re-attributes a package reinstalled after deletion", async () => {
      // Layer 0: curl@7.0 + libc
      // Layer 1: curl deleted → removedPackages: [curl@7.0]
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
      const rootFsLayers = ["sha256:base", "sha256:del", "sha256:reinstall"];
      const manifestLayers = rootFsLayers;

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(3);

      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.entries[0].packages).toContain("curl@7.0.0-r0");
      expect(result.entries[0].packages).toContain("libc@2.35-r1");
      expect(result.entries[0].removedPackages).toBeUndefined();

      expect(result.entries[1].layerIndex).toBe(1);
      expect(result.entries[1].packages).toHaveLength(0);
      expect(result.entries[1].removedPackages).toEqual(["curl@7.0.0-r0"]);

      expect(result.entries[2].layerIndex).toBe(2);
      expect(result.entries[2].packages).toEqual(["curl@8.0.0-r0"]);
      expect(result.entries[2].removedPackages).toBeUndefined();

      expect(result.pkgLayerMap.get("curl@8.0.0-r0")).toEqual({
        layerIndex: 2,
        diffID: "sha256:reinstall",
      });
      expect(result.pkgLayerMap.get("curl@7.0.0-r0")).toEqual({
        layerIndex: 0,
        diffID: "sha256:base",
      });
    });

    it("returns empty entries when no layer has a package DB", async () => {
      const result = await computeLayerAttribution(
        [emptyLayer, emptyLayer],
        AnalysisType.Apk,
        ["sha256:a", "sha256:b"],
        ["sha256:a", "sha256:b"],
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(0);
      expect(result.pkgLayerMap.size).toBe(0);
    });

    it("caps iteration at rootFsLayers length when orderedLayers is longer", async () => {
      const pkgs = [{ name: "libc", version: "2.35-r1" }];
      const orderedLayers = [
        makeApkLayer(makeApkDb(...pkgs)),
        makeApkLayer(makeApkDb(...pkgs, { name: "extra", version: "1.0-r0" })),
      ];
      const rootFsLayers = ["sha256:a"]; // only one — second layer should be ignored
      const manifestLayers = ["sha256:a"];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        manifestLayers,
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].layerIndex).toBe(0);
      expect(result.pkgLayerMap.has("extra@1.0-r0")).toBe(false);
    });

    it("omits instruction when history entry is absent", async () => {
      const orderedLayers = [
        makeApkLayer(makeApkDb({ name: "curl", version: "7.0.0-r0" })),
      ];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        ["sha256:aaa"],
        ["sha256:aaa"],
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries[0].instruction).toBeUndefined();
    });

    it("skips empty_layer history entries when aligning with rootFsLayers", async () => {
      const basePkgs = [{ name: "libc", version: "2.35-r1" }];
      const finalPkgs = [...basePkgs, { name: "curl", version: "7.0.0-r0" }];

      const orderedLayers = [
        makeApkLayer(makeApkDb(...basePkgs)),
        makeApkLayer(makeApkDb(...finalPkgs)),
      ];
      const rootFsLayers = ["sha256:a", "sha256:b"];
      const history = [
        { created_by: "FROM alpine:3.19", empty_layer: false },
        { created_by: "ENV PATH=/usr/local/bin:$PATH", empty_layer: true },
        { created_by: "RUN apk add curl", empty_layer: false },
      ];

      const result = await computeLayerAttribution(
        orderedLayers,
        AnalysisType.Apk,
        rootFsLayers,
        ["sha256:a", "sha256:b"],
        history,
        image,
        undefined,
        [],
      );

      expect(result.entries[0].instruction).toBe("FROM alpine:3.19");
      expect(result.entries[1].instruction).toBe("RUN apk add curl");
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
        ["sha256:base", "sha256:nginx-layer"],
        ["sha256:base", "sha256:nginx-layer"],
        null,
        image,
        undefined,
        [],
      );

      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].packages).toContain("libc6@2.35-0ubuntu3");
      expect(result.entries[1].packages).toContain("nginx@1.18.0-6ubuntu14");
    });
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

  it("merges removedPackages from two managers into the same layer entry", () => {
    const entries: LayerAttributionEntry[] = [
      {
        layerIndex: 1,
        diffID: "sha256:b",
        packages: [],
        removedPackages: ["apt-pkg@1.0"],
      },
      {
        layerIndex: 1,
        diffID: "sha256:b",
        packages: [],
        removedPackages: ["chisel-pkg@2.0"],
      },
    ];
    const result = mergeLayerAttributionEntries(entries);
    expect(result).toHaveLength(1);
    expect(result[0].removedPackages).toContain("apt-pkg@1.0");
    expect(result[0].removedPackages).toContain("chisel-pkg@2.0");
  });

  it("handles a second entry with no removedPackages when first entry has some", () => {
    const entries: LayerAttributionEntry[] = [
      {
        layerIndex: 0,
        diffID: "sha256:a",
        packages: ["a@1.0"],
        removedPackages: ["old@1.0"],
      },
      { layerIndex: 0, diffID: "sha256:a", packages: ["b@1.0"] },
    ];
    const result = mergeLayerAttributionEntries(entries);
    expect(result).toHaveLength(1);
    expect(result[0].removedPackages).toEqual(["old@1.0"]);
    expect(result[0].packages).toContain("a@1.0");
    expect(result[0].packages).toContain("b@1.0");
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
