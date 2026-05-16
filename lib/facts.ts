import { DepGraph } from "@snyk/dep-graph";
import { ApplicationFiles } from "./analyzer/applications/types";
import { JarFingerprint } from "./analyzer/types";
import { DockerFileAnalysis } from "./dockerfile/types";
import { OCIDistributionMetadata } from "./extractor/oci-distribution-metadata";
import {
  AutoDetectedUserInstructions,
  ImageNameInfo,
  ManifestFile,
} from "./types";

export interface DepGraphFact {
  type: "depGraph";
  data: DepGraph;
}

export interface KeyBinariesHashesFact {
  type: "keyBinariesHashes";
  data: string[];
}

export interface ImageLayersFact {
  type: "imageLayers";
  data: string[];
}

export interface DockerfileAnalysisFact {
  type: "dockerfileAnalysis";
  data: DockerFileAnalysis;
}

export interface RootFsFact {
  type: "rootFs";
  data: string[];
}

export interface AutoDetectedUserInstructionsFact {
  type: "autoDetectedUserInstructions";
  data: AutoDetectedUserInstructions;
}
export interface ImageIdFact {
  type: "imageId";
  data: string;
}

export interface ImageNamesFact {
  type: "imageNames";
  data: ImageNameInfo;
}

export interface ImageOsReleasePrettyNameFact {
  type: "imageOsReleasePrettyName";
  data: string;
}

export interface ImageManifestFilesFact {
  type: "imageManifestFiles";
  data: ManifestFile[];
}

export interface TestedFilesFact {
  type: "testedFiles";
  data: string[];
}

export interface ApplicationFilesFact {
  type: "applicationFiles";
  data: ApplicationFiles[];
}

export interface JarFingerprintsFact {
  type: "jarFingerprints";
  data: {
    fingerprints: JarFingerprint[];
    origin: string;
    path: string;
  };
}

export interface ImageLabels {
  type: "imageLabels";
  data: {
    [key: string]: string;
  };
}

export interface ImageSizeBytesFact {
  type: "imageSizeBytes";
  data: number;
}

export interface ImageCreationTimeFact {
  type: "imageCreationTime";
  data: string;
}

export interface LoadedPackagesFact {
  type: "loadedPackages";
  data: string;
}

export interface OCIDistributionMetadataFact {
  type: "ociDistributionMetadata";
  data: OCIDistributionMetadata;
}

export interface PlatformFact {
  type: "platform";
  data: string;
}

export interface PluginVersionFact {
  type: "pluginVersion";
  data: string;
}

export interface ContainerConfigFact {
  type: "containerConfig";
  data: {
    user?: string | null;
    exposedPorts?: string[] | null;
    env?: string[] | null;
    entrypoint?: string[] | null;
    cmd?: string[] | null;
    volumes?: string[] | null;
    workingDir?: string | null;
    stopSignal?: string | null;
    argsEscaped?: boolean | null;
  };
}

export interface HistoryFact {
  type: "history";
  data: Array<{
    created?: string | null;
    author?: string | null;
    createdBy?: string | null;
    comment?: string | null;
    emptyLayer?: boolean | null;
  }>;
}

export interface PluginWarningsFact {
  type: "pluginWarnings";
  data: {
    truncatedFacts?: {
      [key: string]: {
        type: "array" | "string";
        countAboveLimit: number;
      };
    };
    parameterChecks?: string[];
  };
}

export interface BaseRuntime {
  type: string;
  version: string;
}

export interface BaseRuntimesFact {
  type: "baseRuntimes";
  data: BaseRuntime[];
}

export interface LayerAttributionEntry {
  layerIndex: number;
  diffID: string;
  digest?: string;
  instruction?: string;
  /**
   * Every `name@version` observed as introduced in this layer, i.e.
   * present in this layer's package DB (or file set, for app packages)
   * but not the previous layer's. This is a raw event stream — a key
   * MAY appear in `packages` even when the package's files were later
   * removed or replaced by a subsequent layer and so are no longer
   * present in the final merged filesystem.
   *
   * Consult the sibling `finalImagePackages` index on
   * `LayerPackageAttributionFact.data` to determine which introductions
   * survive to the final image.
   */
  packages: string[];
}

/**
 * The layer where a given `name@version` was introduced. Lightweight
 * pointer — the full layer entry (with `digest`, `instruction`, etc.)
 * lives in `LayerPackageAttributionFact.data.entries`.
 */
export interface FinalImagePackageOrigin {
  layerIndex: number;
  diffID: string;
}

export interface LayerPackageAttributionFact {
  type: "layerPackageAttribution";
  data: {
    /**
     * Layer-keyed history of every introduction event observed during
     * the per-layer package-DB diff. Includes events whose effect did
     * not survive to the final image (e.g. an OS package installed in
     * an early layer and removed by a later one).
     */
    entries: LayerAttributionEntry[];
    /**
     * Package-keyed index of every `name@version` present in the final
     * merged filesystem, mapped to the layer(s) where its surviving
     * copy was introduced.
     *
     * Contract:
     * - For OS package managers (apt/apk/rpm/dpkg) the list always has
     *   length 1, because the package manager dedupes — at most one
     *   copy of a given `name@version` exists on disk in the final
     *   image regardless of install/remove/reinstall history.
     * - For application package managers without cross-root dedupe
     *   (e.g. npm with two project roots, each running `npm install`),
     *   a `name@version` can legitimately survive at multiple file
     *   locations introduced by different layers. All such layers are
     *   listed; consumers should attribute a vulnerability to all of
     *   them.
     *
     * Packages that appear in `entries[].packages` but NOT in
     * `finalImagePackages` were introduced and later removed —
     * candidates for a future shadow / remediated-vulnerability view.
     */
    finalImagePackages: Record<string, FinalImagePackageOrigin[]>;
  };
}
