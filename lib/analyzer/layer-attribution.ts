import { ExtractedLayers, HistoryEntry } from "../extractor/types";
import { FinalImagePackageOrigin, LayerAttributionEntry } from "../facts";
import {
  getApkDbFileContent,
  getApkDbFileContentAction,
} from "../inputs/apk/static";
import {
  getAptDbFileContent,
  getDpkgFileContentAction,
} from "../inputs/apt/static";
import {
  getChiselManifestAction,
  getChiselManifestContent,
} from "../inputs/chisel/static";
import {
  getRpmDbFileContent,
  getRpmDbFileContentAction,
  getRpmNdbFileContent,
  getRpmNdbFileContentAction,
  getRpmSqliteDbFileContent,
  getRpmSqliteDbFileContentAction,
} from "../inputs/rpm/static";
import { analyze as apkAnalyze } from "./package-managers/apk";
import { analyze as aptAnalyze } from "./package-managers/apt";
import { analyze as chiselAnalyze } from "./package-managers/chisel";
import {
  analyze as rpmAnalyze,
  mapRpmSqlitePackages,
} from "./package-managers/rpm";
import { AnalysisType, ImagePackagesAnalysis, OSRelease } from "./types";

export interface LayerAttributionResult {
  /**
   * Raw introduction events: every (layer, `name@version`) pair where
   * the package was newly present compared to the previous layer's DB
   * state. Includes events whose effect did not survive to the final
   * image (e.g. an OS package installed early and removed later).
   *
   * The producer does NOT filter out superseded introductions. Live
   * vs. historical disambiguation is the job of `finalImagePackages`,
   * which both this module and downstream consumers (via the fact)
   * use as the source of truth for "what's actually on disk."
   */
  entries: LayerAttributionEntry[];
  /**
   * Package-keyed index of every `name@version` that survived to the
   * final layer's package state, mapped to the layer(s) where its
   * surviving copy was introduced.
   *
   * For OS package managers each list has length 1 (the package manager
   * dedupes). For app package managers without cross-root dedupe a
   * surviving package may legitimately have multiple introducing layers;
   * the type is list-valued from day one to keep the wire format and
   * the internal helper consistent across ecosystems.
   *
   * Used internally by `static-analyzer.ts` to stamp `layerIndex` /
   * `layerDiffId` onto individual package objects, and serialized into
   * `LayerPackageAttributionFact.data.finalImagePackages` for the
   * fact-reading consumer.
   */
  finalImagePackages: Map<string, FinalImagePackageOrigin[]>;
}

export interface AlignedLayerMetadata {
  /**
   * Per-layer diffIDs (uncompressed digests), one per rootfs layer. The size
   * source of truth for the other arrays in this struct.
   */
  diffIDs: string[];
  /**
   * Per-layer manifest digests (compressed). Either length-equal to `diffIDs`
   * (aligned 1:1) or empty when alignment couldn't be trusted.
   */
  manifestDigests: string[];
  /**
   * Per-layer Dockerfile instruction strings. Either length-equal to
   * `diffIDs` (aligned 1:1) or empty when alignment couldn't be trusted.
   */
  instructions: Array<string | undefined>;
}

/**
 * Reconciles per-layer metadata (manifest digests, history-derived
 * instructions) with `rootFsLayers`. Returns aligned arrays of equal length,
 * or empty arrays on length mismatch.
 *
 * Alignment is undetectable after the fact: a missing entry in the middle
 * shifts every subsequent value silently, and we have no shared key to verify
 * against diffIDs. Length equality is the only signal available, so on
 * mismatch we drop the field entirely rather than emit a confidently-wrong
 * value.
 * - manifestLayers is spec'd to align 1:1 with rootfs.diff_ids.
 * - history alignment relies on empty_layer flags being correct, which is
 *   notoriously fragile across squash builds, save round-trips, etc.
 *
 * Intended to be called once per image by the orchestrator. Both the OS and
 * application package attributors then consume the same aligned arrays.
 */
export function alignLayerMetadata(
  rootFsLayers: string[],
  manifestLayers: string[],
  history: HistoryEntry[] | null | undefined,
): AlignedLayerMetadata {
  // Build the candidate instructions list: one entry per non-empty history
  // step, in order, so it can align 1:1 with rootFsLayers. This intentionally
  // differs from `getUserInstructionLayersFromConfig` in extractor/index.ts,
  // which uses a timestamp heuristic to select only the *user-added* layers
  // for Dockerfile attribution; here we want the full per-layer instruction
  // stream so every attribution entry can be annotated.
  const rawInstructions = (history ?? [])
    .filter((h) => !h.empty_layer)
    .map((h) => h.created_by?.trim() || undefined);

  return {
    diffIDs: rootFsLayers,
    manifestDigests:
      manifestLayers.length === rootFsLayers.length ? manifestLayers : [],
    instructions:
      rawInstructions.length === rootFsLayers.length ? rawInstructions : [],
  };
}

/**
 * Returns true if the layer contains a file that was processed by the given
 * extract action. Used to distinguish "layer has no package DB" (return null
 * → skip) from "layer has an empty package DB" (return empty Set → track).
 */
function layerHasAction(layer: ExtractedLayers, actionName: string): boolean {
  return Object.values(layer).some((fileContent) => actionName in fileContent);
}

/**
 * Builds a `name@version` Set from one or more analyzer outputs. Used by
 * every package-manager branch in `parseLayerOsPackages` so the Set-construction
 * loop isn't repeated per branch. Variadic to accommodate RPM, which produces
 * separate analyses for the BDB/NDB and SQLite formats.
 */
function pkgKeySetFromAnalyses(
  ...analyses: ImagePackagesAnalysis[]
): Set<string> {
  const result = new Set<string>();
  for (const analysis of analyses) {
    for (const pkg of analysis.Analysis) {
      result.add(`${pkg.Name}@${pkg.Version}`);
    }
  }
  return result;
}

/**
 * Parses the package DB for a single layer and returns the set of
 * "name@version" keys present in that layer.
 *
 * Returns null when the layer does not contain the package DB file at all
 * (e.g. a COPY or ENV instruction). An empty Set means the DB file exists
 * but is empty (e.g. all packages were removed in this layer).
 */
async function parseLayerOsPackages(
  layer: ExtractedLayers,
  analysisType: AnalysisType,
  targetImage: string,
  osRelease: OSRelease | undefined,
  redHatRepositories: string[],
): Promise<Set<string> | null> {
  if (analysisType === AnalysisType.Apk) {
    if (!layerHasAction(layer, getApkDbFileContentAction.actionName)) {
      return null;
    }
    return pkgKeySetFromAnalyses(
      await apkAnalyze(targetImage, getApkDbFileContent(layer)),
    );
  }

  if (analysisType === AnalysisType.Apt) {
    if (!layerHasAction(layer, getDpkgFileContentAction.actionName)) {
      return null;
    }
    return pkgKeySetFromAnalyses(
      await aptAnalyze(targetImage, getAptDbFileContent(layer), osRelease),
    );
  }

  if (analysisType === AnalysisType.Rpm) {
    const hasBdb = layerHasAction(layer, getRpmDbFileContentAction.actionName);
    const hasNdb = layerHasAction(layer, getRpmNdbFileContentAction.actionName);
    const hasSqlite = layerHasAction(
      layer,
      getRpmSqliteDbFileContentAction.actionName,
    );
    if (!hasBdb && !hasNdb && !hasSqlite) {
      return null;
    }
    // Fetch only the formats present in this layer; absent formats resolve to [].
    // BDB/NDB go through rpmAnalyze; SQLite goes through mapRpmSqlitePackages —
    // matching the main analysis path so package keys are identical.
    const [bdbPkgs, ndbPkgs, sqlitePkgs] = await Promise.all([
      hasBdb ? getRpmDbFileContent(layer) : Promise.resolve([]),
      hasNdb ? getRpmNdbFileContent(layer) : Promise.resolve([]),
      hasSqlite ? getRpmSqliteDbFileContent(layer) : Promise.resolve([]),
    ]);
    const analyses: ImagePackagesAnalysis[] = [];
    if (hasBdb || hasNdb) {
      analyses.push(
        await rpmAnalyze(
          targetImage,
          [...bdbPkgs, ...ndbPkgs],
          redHatRepositories,
          osRelease,
        ),
      );
    }
    if (hasSqlite) {
      analyses.push(
        mapRpmSqlitePackages(
          targetImage,
          sqlitePkgs,
          redHatRepositories,
          osRelease,
        ),
      );
    }
    return pkgKeySetFromAnalyses(...analyses);
  }

  if (analysisType === AnalysisType.Chisel) {
    if (!layerHasAction(layer, getChiselManifestAction.actionName)) {
      return null;
    }
    return pkgKeySetFromAnalyses(
      await chiselAnalyze(targetImage, getChiselManifestContent(layer)),
    );
  }

  return null;
}

/**
 * Computes layer attribution for a single OS package manager.
 *
 * Returns two parallel views of the same observation:
 *
 * - `entries`: the raw event stream — for every layer that mutates the
 *   package DB, the set of `name@version` keys that became newly
 *   present compared to the previous layer. This includes introductions
 *   whose copies were later removed or replaced and so are no longer
 *   on disk in the final image. Consumers that want "everything ever
 *   installed in this image" use this directly.
 *
 * - `finalImagePackages`: the live set — every `name@version` present
 *   in the *last* layer's DB, mapped to the layer(s) where its
 *   surviving copy was introduced. For OS package managers this is
 *   trivially "the latest layer that introduced the key" (dedupe
 *   guarantees at most one live copy); the list-valued shape exists
 *   so the same map type can carry the multi-root app case in the
 *   future.
 *
 * Together these support all three views without further plugin-side
 * derivation: live vulns (lookup in `finalImagePackages`), shadow /
 * remediated vulns (`entries` minus `finalImagePackages`), and
 * forensic / audit (`entries` directly).
 */
export async function computeLayerAttribution(
  orderedLayers: ExtractedLayers[],
  analysisType: AnalysisType,
  layerMetadata: AlignedLayerMetadata,
  targetImage: string,
  osRelease: OSRelease | undefined,
  redHatRepositories: string[],
): Promise<LayerAttributionResult> {
  const { diffIDs, manifestDigests, instructions } = layerMetadata;
  if (orderedLayers.length !== diffIDs.length) {
    // These two arrays are both produced by the extractor and describe the
    // same set of rootfs layers from different angles (file contents vs
    // diffID). A mismatch is an internal invariant violation, not a
    // malformed-image case — fail loudly so the bug surfaces.
    throw new Error(
      `layer attribution: orderedLayers (${orderedLayers.length}) and diffIDs (${diffIDs.length}) must align`,
    );
  }

  // `manifestDigests` and `instructions` are produced by `alignLayerMetadata`
  // and are either length-equal to `diffIDs` or empty when alignment couldn't
  // be trusted. Direct indexing is therefore safe.
  const entries: LayerAttributionEntry[] = [];
  // Per-key reverse index of the most recent layer to introduce each key.
  // Built during the loop; the live filter at the end intersects this with
  // the final layer's package set to produce `finalImagePackages`. For OS
  // each key has a single introducing layer (overwrites on reinstall reflect
  // the surviving copy), so the value is a single origin.
  const latestIntroductionByKey = new Map<string, FinalImagePackageOrigin>();
  const limit = diffIDs.length;

  let previousPkgs = new Set<string>();

  for (let i = 0; i < limit; i++) {
    const diffID = diffIDs[i];
    const digest = manifestDigests[i];
    const instruction = instructions[i];

    const currentPkgs = await parseLayerOsPackages(
      orderedLayers[i],
      analysisType,
      targetImage,
      osRelease,
      redHatRepositories,
    );
    if (currentPkgs === null) {
      // Layer has no package DB file (e.g. COPY/ENV/LABEL instruction).
      // Do not update previousPkgs — the package state has not changed.
      continue;
    }

    const newPkgs: string[] = [];
    for (const key of currentPkgs) {
      if (!previousPkgs.has(key)) {
        newPkgs.push(key);
        // Record this as the latest introduction of `key`. Overwriting on
        // reinstall is intentional: when the live filter below intersects
        // this map with the final package set, the surviving copy's most
        // recent install is what gets reported.
        latestIntroductionByKey.set(key, { layerIndex: i, diffID });
      }
    }

    if (newPkgs.length > 0) {
      const entry: LayerAttributionEntry = {
        layerIndex: i,
        diffID,
        packages: newPkgs,
      };
      if (digest) {
        entry.digest = digest;
      }
      if (instruction !== undefined) {
        entry.instruction = instruction;
      }
      entries.push(entry);
    }

    // Every introduction event stays in `entries`, including events whose
    // effect doesn't survive to the final image (install → remove). Live
    // vs. historical disambiguation happens once below via the final
    // package set, not by filtering entries. This is the load-bearing
    // assumption behind the dual-output contract: `entries` is honest
    // history, `finalImagePackages` is the current state.
    previousPkgs = currentPkgs;
  }

  // Build the live-set index: every key present in the final layer's DB
  // (held by `previousPkgs` after the loop), mapped to the layer where
  // its surviving copy was introduced. Keys that appeared in `entries`
  // but not in the final set were removed and not reinstalled — they
  // are deliberately left out, and their introduction events remain in
  // `entries` for shadow-vuln / audit consumers.
  //
  // The list-valued shape (`Array<FinalImagePackageOrigin>`) is uniform
  // across OS and app ecosystems even though OS lists are always
  // length 1. App attribution will populate multi-element lists when
  // a package legitimately survives at multiple file locations
  // introduced by different layers (e.g. two `npm install` roots).
  const finalImagePackages = new Map<string, FinalImagePackageOrigin[]>();
  for (const key of previousPkgs) {
    const origin = latestIntroductionByKey.get(key);
    if (origin) {
      finalImagePackages.set(key, [origin]);
    }
  }

  return { entries, finalImagePackages };
}

/**
 * Merges attribution entries produced by multiple package managers into a
 * single list sorted by layer index. When two managers both write entries for
 * the same layer (e.g. APT and Chisel in a mixed image), their package lists
 * are concatenated. Layer metadata (diffID, digest, instruction) is taken
 * from the first entry seen for that layer index.
 */
export function mergeLayerAttributionEntries(
  entries: LayerAttributionEntry[],
): LayerAttributionEntry[] {
  const byLayer = new Map<number, LayerAttributionEntry>();

  for (const entry of entries) {
    const existing = byLayer.get(entry.layerIndex);
    if (!existing) {
      byLayer.set(entry.layerIndex, {
        ...entry,
        packages: [...entry.packages],
      });
    } else {
      existing.packages.push(...entry.packages);
    }
  }

  return Array.from(byLayer.values()).sort(
    (a, b) => a.layerIndex - b.layerIndex,
  );
}
