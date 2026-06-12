import { depFullName } from "../dependency-tree";
import { getErrorMessage } from "../error-utils";
import { ExtractedLayers, HistoryEntry } from "../extractor/types";
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
import {
  AnalysisType,
  ImagePackagesAnalysis,
  IntroducingLayerByPackage,
  OSRelease,
} from "./types";

/**
 * Checks whether the OCI "non-empty history entries map 1:1 to
 * `rootfs.diff_ids[]`" rule holds for this image. Returns a warning
 * string when it does not, otherwise `undefined`.
 *
 * The plugin's own per-package attribution path is keyed by diffID and
 * does not depend on `history` alignment — those labels are correct
 * either way. The backend performs the diffID -> `createdBy` join at
 * read time using the separately-emitted `rootFs` and `history` facts,
 * and it is the backend's responsibility to detect misalignment and
 * decide whether to surface instruction text. The plugin only emits a
 * warning so a human running a scan can see "instructions may not be
 * shown" without needing to dig into backend logs.
 *
 * Alignment failure is silent at the OCI level — there is no shared key
 * between `history` and `diff_ids[]`. Length equality is the only signal
 * available, and it is notoriously fragile across squash builds,
 * `docker save` round-trips, and some non-Docker builders (Jib, ko,
 * apko, Bazel `rules_docker`).
 *
 * @param history `null`/`undefined` is treated as "no history to align
 *   against," which is not an error — there is simply nothing
 *   to join. Only a length mismatch between non-empty history
 *   entries and rootfs layers produces a warning.
 */
export function checkHistoryAlignment(
  rootFsLayers: string[],
  history: HistoryEntry[] | null | undefined,
): string | undefined {
  if (history === null || history === undefined) {
    return undefined;
  }
  const nonEmptyHistoryCount = history.filter((h) => !h.empty_layer).length;
  if (nonEmptyHistoryCount === rootFsLayers.length) {
    return undefined;
  }
  return (
    `Layer attribution: image history does not align 1:1 with rootfs layers ` +
    `(history has ${nonEmptyHistoryCount} non-empty entries, rootfs has ${rootFsLayers.length} layers). ` +
    `Per-package layer attribution will still be reported, but the originating Dockerfile instruction may not be shown.`
  );
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
 * Builds a `<fullName>@<version>` Set from one or more analyzer outputs,
 * where `fullName` is the same string the dep-graph builder uses for the
 * package node (`<source>/<binary>` when a source/origin is known,
 * otherwise just `<binary>`). Sharing `depFullName` with the dep-graph
 * side is what lets `response-builder` annotate dep-graph nodes with the
 * `dockerLayerDiffId` label by direct key lookup, with no string surgery.
 *
 * Variadic to accommodate RPM, which produces separate analyses for the
 * BDB/NDB and SQLite formats.
 */
function pkgKeySetFromAnalyses(
  ...analyses: ImagePackagesAnalysis[]
): Set<string> {
  const result = new Set<string>();
  for (const analysis of analyses) {
    for (const pkg of analysis.Analysis) {
      result.add(`${depFullName(pkg)}@${pkg.Version}`);
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
  switch (analysisType) {
    case AnalysisType.Apk: {
      if (!layerHasAction(layer, getApkDbFileContentAction.actionName)) {
        return null;
      }
      return pkgKeySetFromAnalyses(
        await apkAnalyze(targetImage, getApkDbFileContent(layer)),
      );
    }

    case AnalysisType.Apt: {
      if (!layerHasAction(layer, getDpkgFileContentAction.actionName)) {
        return null;
      }
      return pkgKeySetFromAnalyses(
        await aptAnalyze(targetImage, getAptDbFileContent(layer), osRelease),
      );
    }

    case AnalysisType.Rpm: {
      const hasBdb = layerHasAction(
        layer,
        getRpmDbFileContentAction.actionName,
      );
      const hasNdb = layerHasAction(
        layer,
        getRpmNdbFileContentAction.actionName,
      );
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

    case AnalysisType.Chisel: {
      if (!layerHasAction(layer, getChiselManifestAction.actionName)) {
        return null;
      }
      return pkgKeySetFromAnalyses(
        await chiselAnalyze(targetImage, getChiselManifestContent(layer)),
      );
    }

    default:
      // Binaries/Linux (and any future non-OS-PM type) have no per-layer
      // package DB to diff, so there is nothing to attribute.
      return null;
  }
}

/**
 * Computes per-package layer attribution for a single OS package manager
 * (Apk, Apt, Rpm, or Chisel). Returns the `<fullName>@<version>` -> diffID
 * map for every package present in the *final* layer's DB.
 *
 * Earlier introductions whose copies were later removed do not appear in
 * the result. The OS package manager dedupes, so for OS ecosystems each
 * surviving key has exactly one introducing layer (the most recent layer
 * to install or reinstall the surviving copy).
 *
 * The image-wide orchestrator is `computeOsLayerAttribution`; call this
 * directly only when you already know the target ecosystem.
 */
export async function computeOsPackageManagerLayerAttribution(
  orderedLayers: ExtractedLayers[],
  analysisType: AnalysisType,
  diffIDs: string[],
  targetImage: string,
  osRelease: OSRelease | undefined,
  redHatRepositories: string[],
): Promise<IntroducingLayerByPackage> {
  if (orderedLayers.length !== diffIDs.length) {
    // These two arrays are both produced by the extractor and describe the
    // same set of rootfs layers from different angles (file contents vs
    // diffID). A mismatch is an internal invariant violation, not a
    // malformed-image case — fail loudly so the bug surfaces.
    throw new Error(
      `layer attribution: orderedLayers (${orderedLayers.length}) and diffIDs (${diffIDs.length}) must align`,
    );
  }

  // Per-key reverse index of the most recent layer to introduce each key.
  // Built during the loop; the live filter at the end intersects this with
  // the final layer's package set to produce the returned map.
  const latestIntroductionByKey: IntroducingLayerByPackage = new Map();
  let previousPkgs = new Set<string>();

  for (let i = 0; i < diffIDs.length; i++) {
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

    for (const key of currentPkgs) {
      if (!previousPkgs.has(key)) {
        // We only record a layer when the key was absent from the
        // immediately-preceding layer's snapshot. That covers both
        // first installs and reinstalls after removal (the intermediate
        // empty-DB layer wipes `previousPkgs`, so the new install is
        // treated as fresh). A same-version reinstall *without* an
        // intermediate removal is rare in practice and would be
        // attributed to the earlier install — but the survivor-set
        // intersection below still produces a correct diffID for the
        // copy that ends up on disk.
        latestIntroductionByKey.set(key, diffIDs[i]);
      }
    }

    previousPkgs = currentPkgs;
  }

  // Keep only packages that survive in the final layer's DB.
  const finalImagePackages: IntroducingLayerByPackage = new Map();
  for (const key of previousPkgs) {
    const diffID = latestIntroductionByKey.get(key);
    if (diffID) {
      finalImagePackages.set(key, diffID);
    }
  }

  return finalImagePackages;
}

/**
 * Result of image-wide OS-package layer attribution.
 *
 * `warnings` are human-readable, non-fatal messages (a per-ecosystem
 * failure, or a cross-ecosystem key collision). They share the string
 * shape of `checkHistoryAlignment`'s return value so a caller can collect
 * both into one list (e.g. the `pluginWarnings` fact). `introducingLayerByPackage`
 * is always usable; warnings only flag that coverage may be incomplete.
 */
export interface OsLayerAttribution {
  introducingLayerByPackage: IntroducingLayerByPackage;
  warnings: string[];
}

/**
 * Image-wide OS-package layer attribution. Orchestrates the per-PM
 * `computeOsPackageManagerLayerAttribution` calls and merges their outputs
 * into a single `<fullName>@<version>` -> diffID map, returning any
 * non-fatal warnings alongside it (see `OsLayerAttribution`).
 *
 * The top-level `Promise.all` in `static-analyzer.ts` produces one
 * `ImagePackagesAnalysis` per DB *format* — e.g. RPM BDB/NDB and RPM SQLite
 * are separate results, both tagged `AnalysisType.Rpm`; regular APT and
 * distroless APT are separate results, both tagged `AnalysisType.Apt`. The
 * per-PM helper is keyed on `AnalysisType` and already reads every DB
 * format for that ecosystem per layer, so we must call it once per
 * *ecosystem*, not once per *result* — otherwise duplicate ecosystem-level
 * invocations would write the same key twice.
 *
 * Cross-ecosystem key collisions are not expected in practice — each OS
 * PM produces a disjoint `<source>/<binary>` namespace, and real images
 * don't carry two OS PMs at once. If one ever fires, it indicates either
 * a bug in our key shape or an exotic image we haven't accounted for, so
 * we record a warning (last-writer-wins is applied so attribution still
 * ships) instead of silently overwriting.
 *
 * Per-ecosystem failures (a per-PM `await` that throws) are recorded as
 * warnings too and don't abort attribution for the other ecosystems —
 * losing one ecosystem's view is strictly better than losing all of them.
 */
export async function computeOsLayerAttribution(
  analyses: ImagePackagesAnalysis[],
  orderedLayers: ExtractedLayers[],
  diffIDs: string[],
  targetImage: string,
  osRelease: OSRelease | undefined,
  redHatRepositories: string[],
): Promise<OsLayerAttribution> {
  const analysisTypes = Array.from(
    new Set(
      analyses.filter((a) => a.Analysis.length > 0).map((a) => a.AnalyzeType),
    ),
  );

  const introducingLayerByPackage: IntroducingLayerByPackage = new Map();
  const warnings: string[] = [];

  for (const analysisType of analysisTypes) {
    try {
      const survivors = await computeOsPackageManagerLayerAttribution(
        orderedLayers,
        analysisType,
        diffIDs,
        targetImage,
        osRelease,
        redHatRepositories,
      );
      for (const [key, diffID] of survivors) {
        const previous = introducingLayerByPackage.get(key);
        if (previous !== undefined) {
          warnings.push(
            `Layer attribution: unexpected cross-ecosystem collision on key ` +
              `"${key}" (already attributed to ${previous}); last-writer-wins applied.`,
          );
        }
        introducingLayerByPackage.set(key, diffID);
      }
    } catch (err) {
      warnings.push(
        `Layer attribution: failed to attribute ${analysisType} packages: ${getErrorMessage(
          err,
        )}.`,
      );
    }
  }

  return { introducingLayerByPackage, warnings };
}
