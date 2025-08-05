import * as Debug from "debug";
import * as path from "path";
import { parseCycloneDXJSON, parseCycloneDXXML } from "./cyclonedx-parser";
import {
  parseSPDXJSON,
  parseSPDXRDF,
  parseSPDXXML,
  parseSPDXYAML,
} from "./spdx-parser";
import { ParsedSBOM, SBOMDocument, SBOMFormat } from "./types";

const debug = Debug("snyk:sbom:parser");

/**
 * Detects the SBOM format based on file path and content
 */
export function detectSBOMFormat(
  filePath: string,
  content: string,
): SBOMFormat {
  const normalizedPath = path.normalize(filePath).toLowerCase();

  // Try to detect from file extension first
  if (
    normalizedPath.endsWith(".spdx.json") ||
    normalizedPath.endsWith(".spdx")
  ) {
    return SBOMFormat.SPDX_JSON;
  }
  if (normalizedPath.endsWith(".spdx.xml")) {
    return SBOMFormat.SPDX_XML;
  }
  if (normalizedPath.endsWith(".spdx.rdf")) {
    return SBOMFormat.SPDX_RDF;
  }
  if (
    normalizedPath.endsWith(".spdx.yaml") ||
    normalizedPath.endsWith(".spdx.yml")
  ) {
    return SBOMFormat.SPDX_YAML;
  }
  if (normalizedPath.endsWith(".cyclonedx.json")) {
    return SBOMFormat.CYCLONEDX_JSON;
  }
  if (normalizedPath.endsWith(".cyclonedx.xml")) {
    return SBOMFormat.CYCLONEDX_XML;
  }

  // Try to detect from content
  const trimmedContent = content.trim();

  // Check for JSON content
  if (trimmedContent.startsWith("{")) {
    try {
      const jsonDoc = JSON.parse(content);

      // Check for SPDX JSON
      if (jsonDoc.spdxVersion && jsonDoc.dataLicense) {
        return SBOMFormat.SPDX_JSON;
      }

      // Check for CycloneDX JSON
      if (jsonDoc.bomFormat === "CycloneDX" && jsonDoc.specVersion) {
        return SBOMFormat.CYCLONEDX_JSON;
      }
    } catch (error) {
      // Not valid JSON
    }
  }

  // Check for XML content
  if (trimmedContent.startsWith("<")) {
    if (content.includes("spdxVersion") || content.includes("SPDXRef")) {
      return SBOMFormat.SPDX_XML;
    }
    if (content.includes("cyclonedx") || content.includes("bomFormat")) {
      return SBOMFormat.CYCLONEDX_XML;
    }
  }

  // Check for YAML content (basic heuristics)
  if (content.includes("spdxVersion:") || content.includes("dataLicense:")) {
    return SBOMFormat.SPDX_YAML;
  }

  debug(`Could not detect SBOM format for file: ${filePath}`);
  return SBOMFormat.UNKNOWN;
}

/**
 * Parses an SBOM file based on its detected format
 */
export function parseSBOM(
  filePath: string,
  content: string,
): ParsedSBOM | null {
  const format = detectSBOMFormat(filePath, content);

  debug(`Detected SBOM format: ${format} for file: ${filePath}`);

  let document: SBOMDocument | null = null;

  switch (format) {
    case SBOMFormat.SPDX_JSON:
      document = parseSPDXJSON(content);
      break;
    case SBOMFormat.SPDX_XML:
      document = parseSPDXXML(content);
      break;
    case SBOMFormat.SPDX_RDF:
      document = parseSPDXRDF(content);
      break;
    case SBOMFormat.SPDX_YAML:
      document = parseSPDXYAML(content);
      break;
    case SBOMFormat.CYCLONEDX_JSON:
      document = parseCycloneDXJSON(content);
      break;
    case SBOMFormat.CYCLONEDX_XML:
      document = parseCycloneDXXML(content);
      break;
    default:
      debug(`Unsupported SBOM format: ${format}`);
      return null;
  }

  if (!document) {
    debug(`Failed to parse SBOM file: ${filePath}`);
    return null;
  }

  return {
    format,
    document,
    filePath,
  };
}

/**
 * Parses multiple SBOM files from extracted layers
 */
export function parseSBOMFiles(sbomFiles: {
  [filePath: string]: string;
}): ParsedSBOM[] {
  const parsedSBOMs: ParsedSBOM[] = [];

  for (const [filePath, content] of Object.entries(sbomFiles)) {
    try {
      const parsed = parseSBOM(filePath, content);
      if (parsed) {
        parsedSBOMs.push(parsed);
        debug(`Successfully parsed SBOM: ${filePath} (${parsed.format})`);
      }
    } catch (error) {
      debug(`Error parsing SBOM file ${filePath}: ${error.message}`);
    }
  }

  debug(
    `Parsed ${parsedSBOMs.length} SBOM files out of ${
      Object.keys(sbomFiles).length
    } found`,
  );
  return parsedSBOMs;
}

export * from "./types";
export * from "./spdx-parser";
export * from "./cyclonedx-parser";
