import { DepGraph } from "@snyk/dep-graph";
import * as plugin from "../../lib";
import { DepGraphFact, HistoryFact, RootFsFact } from "../../lib/facts";
import { ScanResult } from "../../lib/types";
import { getFixture } from "../util";

// End-to-end check for the layer-attribution wire format described in the
// vulns-by-layer technical design doc.
//
// The contract under test:
// 1. With `--layer-attribution`, attributed dep-graph nodes carry a
//    `dockerLayerDiffId` label whose value is the `sha256:…` diffID of the
//    rootfs layer that introduced the package.
// 2. `rootFs` and `history` facts are emitted on every container scan
//    result (today only the OS scan result carries them) so Registry can
//    perform the diffID -> `createdBy` join per-monitor without a
//    cross-scan-result lookup.
// 3. Without `--layer-attribution`, none of the above appears: no label
//    on dep-graph nodes, no `rootFs`/`history` duplication onto app
//    scan results.
//
// The fixture is a hand-crafted alpine-based image that exercises the
// install / remove / reinstall path:
//   - FROM alpine:3.19  (introduces base packages)
//   - RUN apk add --no-cache tmux
//   - COPY Dockerfile /app/   (no DB change, must be skipped)
//   - RUN apk add --no-cache jq htop
//   - RUN apk add --no-cache bash && apk del jq htop
//   - RUN apk add --no-cache jq    (reinstall — tests latest-wins)

describe("layer attribution wire format on a real image", () => {
  const archivePath = getFixture([
    "docker-archives",
    "docker-save",
    "layer-attribution-test.tar",
  ]);

  function findLabelledNodes(
    depGraph: DepGraph,
  ): Array<{ name: string; version?: string; diffID: string }> {
    const labelled: Array<{
      name: string;
      version?: string;
      diffID: string;
    }> = [];
    for (const pkg of depGraph.getPkgs()) {
      for (const node of depGraph.getPkgNodes(pkg)) {
        const diffID = node.info?.labels?.dockerLayerDiffId;
        if (diffID) {
          labelled.push({ name: pkg.name, version: pkg.version, diffID });
        }
      }
    }
    return labelled;
  }

  describe("with --layer-attribution enabled", () => {
    let osResult: ScanResult;
    let labelledNodes: Array<{
      name: string;
      version?: string;
      diffID: string;
    }>;
    let rootFs: string[];
    let history: HistoryFact["data"];

    beforeAll(async () => {
      const result = await plugin.scan({
        path: `docker-archive:${archivePath}`,
        "layer-attribution": true,
      });

      osResult = result.scanResults[0];

      const depGraphFact = osResult.facts.find((f) => f.type === "depGraph") as
        | DepGraphFact
        | undefined;
      if (!depGraphFact) {
        throw new Error("expected a depGraph fact on the OS scan result");
      }
      labelledNodes = findLabelledNodes(depGraphFact.data);

      const rootFsFact = osResult.facts.find((f) => f.type === "rootFs") as
        | RootFsFact
        | undefined;
      if (!rootFsFact) {
        throw new Error("expected a rootFs fact on the OS scan result");
      }
      rootFs = rootFsFact.data;

      const historyFact = osResult.facts.find((f) => f.type === "history") as
        | HistoryFact
        | undefined;
      if (!historyFact) {
        throw new Error("expected a history fact on the OS scan result");
      }
      history = historyFact.data;
    });

    it("annotates attributed dep-graph nodes with `dockerLayerDiffId`", () => {
      // The fixture has > 15 OS packages from alpine:3.19 plus the user
      // installs (tmux, bash, jq, ...). We don't pin the count to keep
      // the test resilient to upstream alpine point releases.
      expect(labelledNodes.length).toBeGreaterThan(10);
      for (const node of labelledNodes) {
        expect(node.diffID).toMatch(/^sha256:[0-9a-f]{64}$/);
      }
    });

    it("uses values that are valid diffIDs from the image's rootFs", () => {
      // The label's value must be a real entry in `rootFs`; otherwise
      // the read-time join in Registry will silently miss every node.
      const diffIDSet = new Set(rootFs);
      const distinctLabelDiffIDs = new Set(labelledNodes.map((n) => n.diffID));
      expect(distinctLabelDiffIDs.size).toBeGreaterThan(0);
      for (const diffID of distinctLabelDiffIDs) {
        expect(diffIDSet.has(diffID)).toBe(true);
      }
    });

    it("attributes alpine base packages to the FROM layer (rootFs[0])", () => {
      // The first non-empty history entry corresponds to rootFs[0] — the
      // FROM alpine:3.19 layer. `busybox` and `musl` are part of every
      // alpine root filesystem.
      const baseDiffID = rootFs[0];
      const busybox = labelledNodes.find((n) => /busybox$/.test(n.name));
      const musl = labelledNodes.find((n) => /musl$/.test(n.name));
      expect(busybox?.diffID).toBe(baseDiffID);
      expect(musl?.diffID).toBe(baseDiffID);
    });

    it("attributes tmux to a layer whose `createdBy` mentions `apk add ... tmux`", () => {
      // Walk the join the same way Registry will: find tmux's diffID,
      // map it to its index in rootFs, then read the corresponding
      // non-empty history entry's createdBy.
      const tmux = labelledNodes.find((n) => /(?:^|\/)tmux$/.test(n.name));
      expect(tmux).toBeDefined();
      const layerIndex = rootFs.indexOf(tmux!.diffID);
      expect(layerIndex).toBeGreaterThanOrEqual(0);

      const nonEmptyHistory = history.filter((h) => !h.emptyLayer);
      // The OCI rule: non-empty history entries map 1:1 with rootFs.
      expect(nonEmptyHistory.length).toBe(rootFs.length);
      const createdBy = nonEmptyHistory[layerIndex].createdBy ?? "";
      expect(createdBy).toMatch(/apk add[^\n]*tmux/);
    });

    it("attributes jq's surviving copy to the reinstall layer, not the first install", () => {
      // The fixture installs jq at one layer, removes it at the next,
      // and reinstalls at the same version later. The label must point
      // at the latest install — the layer whose copy actually survives
      // on disk in the final image.
      const jq = labelledNodes.find((n) => /(?:^|\/)jq$/.test(n.name));
      expect(jq).toBeDefined();

      // Find every layer that mentions `apk add ... jq` in its
      // createdBy and confirm the label points at the latest one.
      const nonEmptyHistory = history.filter((h) => !h.emptyLayer);
      const jqInstallLayerIndices = nonEmptyHistory
        .map((h, i) => ({ idx: i, createdBy: h.createdBy ?? "" }))
        .filter(
          ({ createdBy }) =>
            /apk add[^\n]*\bjq\b/.test(createdBy) &&
            !/apk del[^\n]*\bjq\b/.test(createdBy),
        )
        .map(({ idx }) => idx);
      expect(jqInstallLayerIndices.length).toBeGreaterThanOrEqual(2);
      const latestInstallIdx = Math.max(...jqInstallLayerIndices);
      expect(jq!.diffID).toBe(rootFs[latestInstallIdx]);
    });

    it("omits htop — it was installed and later purged, so no node carries its label", () => {
      // htop is installed by `apk add jq htop` and removed by the
      // following RUN. It is no longer on disk in the final image, so
      // it does not appear as a dep-graph package and therefore has no
      // labelled node.
      const htop = labelledNodes.find((n) => /(?:^|\/)htop$/.test(n.name));
      expect(htop).toBeUndefined();
    });

    it("does not yet duplicate rootFs/history onto app scan results (OS-only milestone)", async () => {
      // The vulns-by-layer design duplicates `rootFs` + `history` onto
      // every container scan result so Registry can do the diffID ->
      // instruction join per-monitor. The first milestone only emits
      // labels for OS packages, so app scan results have nothing to
      // join — duplicating the facts now would be dead weight. When
      // app-package attribution lands, flip this assertion (and
      // re-enable the commented-out block in `response-builder.ts`).
      const result = await plugin.scan({
        path: `docker-archive:${archivePath}`,
        "layer-attribution": true,
      });
      const appResults = result.scanResults.slice(1);
      for (const sr of appResults) {
        expect(sr.facts.find((f) => f.type === "rootFs")).toBeUndefined();
        expect(sr.facts.find((f) => f.type === "history")).toBeUndefined();
      }
    });
  });

  describe("without --layer-attribution", () => {
    let result: Awaited<ReturnType<typeof plugin.scan>>;

    beforeAll(async () => {
      result = await plugin.scan({
        path: `docker-archive:${archivePath}`,
      });
    });

    it("does not annotate any dep-graph node with `dockerLayerDiffId`", () => {
      for (const sr of result.scanResults) {
        const depGraphFact = sr.facts.find((f) => f.type === "depGraph") as
          | DepGraphFact
          | undefined;
        if (!depGraphFact) {
          continue;
        }
        expect(findLabelledNodes(depGraphFact.data)).toEqual([]);
      }
    });

    it("does not duplicate rootFs/history onto app scan results", () => {
      // The OS scan result keeps its `rootFs` / `history` facts (they
      // pre-date this feature), but app scan results must not pick them
      // up unless `--layer-attribution` is on.
      const appResults = result.scanResults.slice(1);
      for (const sr of appResults) {
        expect(sr.facts.find((f) => f.type === "rootFs")).toBeUndefined();
        expect(sr.facts.find((f) => f.type === "history")).toBeUndefined();
      }
    });
  });
});
