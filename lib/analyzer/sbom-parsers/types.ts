export interface SBOMPackage {
  name: string;
  version: string;
  purl?: string;
  license?: string;
  supplier?: string;
  downloadLocation?: string;
  dependencies?: string[];
  checksums?: { [algorithm: string]: string };
  copyrightText?: string;
  sourceInfo?: string;
}

export interface SBOMDocument {
  name: string;
  version?: string;
  dataLicense?: string;
  documentNamespace?: string;
  creationInfo?: {
    created: string;
    creators: string[];
    licenseListVersion?: string;
  };
  packages: SBOMPackage[];
  relationships?: Array<{
    relatedSpdxElement: string;
    relationshipType: string;
    spdxElementId: string;
  }>;
}

export enum SBOMFormat {
  SPDX_JSON = "spdx-json",
  SPDX_XML = "spdx-xml",
  SPDX_RDF = "spdx-rdf",
  SPDX_YAML = "spdx-yaml",
  CYCLONEDX_JSON = "cyclonedx-json",
  CYCLONEDX_XML = "cyclonedx-xml",
  UNKNOWN = "unknown",
}

export interface ParsedSBOM {
  format: SBOMFormat;
  document: SBOMDocument;
  filePath: string;
}
