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
