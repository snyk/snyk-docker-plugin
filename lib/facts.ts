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

export interface BaseRuntime {
  type: string;
  version: string;
}

export interface BaseRuntimesFact {
  type: "baseRuntimes";
  data: BaseRuntime[];
}
