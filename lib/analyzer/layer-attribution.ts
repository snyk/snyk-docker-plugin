import { ExtractedLayers, HistoryEntry } from "../extractor/types";
import { LayerAttributionEntry } from "../facts";
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
import { analyze as rpmAnalyze } from "./package-managers/rpm";
import { AnalysisType } from "./types";

export interface LayerAttributionResult {
  entries: LayerAttributionEntry[];
  pkgLayerMap: Map<string, { layerIndex: number; diffID: string }>;
}

function buildHistoryInstructions(
  history: HistoryEntry[] | null | undefined,
): string[] {
  if (!history) {
    return [];
  }
  return history.filter((h) => !h.empty_layer).map((h) => h.created_by ?? "");
}

function pkgKey(name: string, version: string): string {
  return `${name}@${version}`;
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
 * Parses the package DB for a single layer and returns the set of
 * "name@version" keys present in that layer.
 *
 * Returns null when the layer does not contain the package DB file at all
 * (e.g. a COPY or ENV instruction). An empty Set means the DB file exists
 * but is empty (e.g. all packages were removed in this layer).
 */
async function parseLayerPackages(
  layer: ExtractedLayers,
  analysisType: AnalysisType,
  targetImage: string,
): Promise<Set<string> | null> {
  if (analysisType === AnalysisType.Apk) {
    if (!layerHasAction(layer, getApkDbFileContentAction.actionName)) {
      return null;
    }
    const content = getApkDbFileContent(layer);
    const analysis = await apkAnalyze(targetImage, content);
    const result = new Set<string>();
    for (const pkg of analysis.Analysis) {
      result.add(pkgKey(pkg.Name, pkg.Version));
    }
    return result;
  }

  if (analysisType === AnalysisType.Apt) {
    if (!layerHasAction(layer, getDpkgFileContentAction.actionName)) {
      return null;
    }
    const aptFiles = getAptDbFileContent(layer);
    const analysis = await aptAnalyze(targetImage, aptFiles);
    const result = new Set<string>();
    for (const pkg of analysis.Analysis) {
      result.add(pkgKey(pkg.Name, pkg.Version));
    }
    return result;
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
    const [bdbPkgs, ndbPkgs, sqlitePkgs] = await Promise.all([
      hasBdb ? getRpmDbFileContent(layer) : Promise.resolve([]),
      hasNdb ? getRpmNdbFileContent(layer) : Promise.resolve([]),
      hasSqlite ? getRpmSqliteDbFileContent(layer) : Promise.resolve([]),
    ]);
    const analysis = await rpmAnalyze(
      targetImage,
      [...bdbPkgs, ...ndbPkgs, ...sqlitePkgs],
      [],
    );
    const result = new Set<string>();
    for (const pkg of analysis.Analysis) {
      result.add(pkgKey(pkg.Name, pkg.Version));
    }
    return result;
  }

  if (analysisType === AnalysisType.Chisel) {
    if (!layerHasAction(layer, getChiselManifestAction.actionName)) {
      return null;
    }
    const pkgs = getChiselManifestContent(layer);
    const analysis = await chiselAnalyze(targetImage, pkgs);
    const result = new Set<string>();
    for (const pkg of analysis.Analysis) {
      result.add(pkgKey(pkg.Name, pkg.Version));
    }
    return result;
  }

  return null;
}

export async function computeLayerAttribution(
  orderedLayers: ExtractedLayers[],
  analysisType: AnalysisType,
  rootFsLayers: string[],
  manifestLayers: string[],
  history: HistoryEntry[] | null | undefined,
  targetImage: string,
): Promise<LayerAttributionResult> {
  const instructions = buildHistoryInstructions(history);
  const entries: LayerAttributionEntry[] = [];
  const pkgLayerMap = new Map<string, { layerIndex: number; diffID: string }>();
  const limit = Math.min(orderedLayers.length, rootFsLayers.length);

  let previousPkgs = new Set<string>();

  for (let i = 0; i < limit; i++) {
    const diffID = rootFsLayers[i];
    // Explicit bounds guard: manifestLayers and instructions may be shorter
    // than rootFsLayers for malformed or partially-described images.
    const digest = i < manifestLayers.length ? manifestLayers[i] : undefined;
    const instruction = i < instructions.length ? instructions[i] : undefined;

    const currentPkgs = await parseLayerPackages(
      orderedLayers[i],
      analysisType,
      targetImage,
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
        pkgLayerMap.set(key, { layerIndex: i, diffID });
      }
    }

    const removedPkgs: string[] = [];
    for (const key of previousPkgs) {
      if (!currentPkgs.has(key)) {
        removedPkgs.push(key);
      }
    }

    if (newPkgs.length > 0 || removedPkgs.length > 0) {
      const entry: LayerAttributionEntry = {
        layerIndex: i,
        diffID,
        packages: newPkgs,
      };
      if (digest) {
        entry.digest = digest;
      }
      if (instruction) {
        entry.instruction = instruction;
      }
      if (removedPkgs.length > 0) {
        entry.removedPackages = removedPkgs;
      }
      entries.push(entry);
    }

    previousPkgs = currentPkgs;
  }

  return { entries, pkgLayerMap };
}

/**
 * Merges attribution entries produced by multiple package managers into a
 * single list sorted by layer index. When two managers both write entries for
 * the same layer (e.g. APT and Chisel in a mixed image), their package lists
 * and removedPackages lists are combined. Layer metadata (diffID, digest,
 * instruction) is taken from the first entry seen for that layer index.
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
        removedPackages: entry.removedPackages
          ? [...entry.removedPackages]
          : undefined,
      });
    } else {
      existing.packages.push(...entry.packages);
      if (entry.removedPackages && entry.removedPackages.length > 0) {
        if (!existing.removedPackages) {
          existing.removedPackages = [...entry.removedPackages];
        } else {
          existing.removedPackages.push(...entry.removedPackages);
        }
      }
    }
  }

  return Array.from(byLayer.values()).sort(
    (a, b) => a.layerIndex - b.layerIndex,
  );
}
