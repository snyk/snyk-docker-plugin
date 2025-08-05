import * as Debug from "debug";
import { SBOMDocument, SBOMPackage } from "../types";

export interface SPDXPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  downloadLocation?: string;
  filesAnalyzed?: boolean;
  licenseConcluded?: string;
  licenseDeclared?: string;
  copyrightText?: string;
  externalRefs?: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
  checksums?: Array<{
    algorithm: string;
    checksumValue: string;
  }>;
  supplier?: string;
}

/**
 * Abstract base class for SPDX parsers
 */
export abstract class BaseSPDXParser {
  protected debug: Debug.Debugger;

  constructor(formatName: string) {
    this.debug = Debug(`snyk:sbom:spdx:${formatName}`);
  }

  /**
   * Abstract method to parse SPDX content - must be implemented by subclasses
   */
  public abstract parse(content: string): SBOMDocument | null;

  /**
   * Validate if content can be parsed by this parser
   */
  public abstract canParse(content: string): boolean;

  /**
   * Convert SPDXPackage to SBOMPackage format
   */
  protected convertToSBOMPackage(spdxPackage: SPDXPackage): SBOMPackage {
    const sbomPackage: SBOMPackage = {
      name: spdxPackage.name,
      version: spdxPackage.versionInfo || "unknown",
      license: spdxPackage.licenseConcluded || spdxPackage.licenseDeclared,
      supplier: spdxPackage.supplier,
      downloadLocation: spdxPackage.downloadLocation,
      copyrightText: spdxPackage.copyrightText,
      dependencies: [], // Will be populated by relationship processing
      checksums: {},
    };

    // Extract PURL from external references
    if (spdxPackage.externalRefs) {
      for (const extRef of spdxPackage.externalRefs) {
        if (
          extRef.referenceType === "purl" ||
          (extRef.referenceCategory === "PACKAGE-MANAGER" &&
            extRef.referenceType === "purl")
        ) {
          sbomPackage.purl = extRef.referenceLocator;
          break;
        }
      }
    }

    // Convert checksums
    if (spdxPackage.checksums) {
      for (const checksum of spdxPackage.checksums) {
        sbomPackage.checksums![checksum.algorithm.toLowerCase()] =
          checksum.checksumValue;
      }
    }

    return sbomPackage;
  }

  /**
   * Build creation info structure
   */
  protected buildCreationInfo(
    created: string,
    creators: string[],
    licenseListVersion?: string,
  ) {
    return {
      created: created || "",
      creators: creators || [],
      licenseListVersion,
    };
  }

  /**
   * Validate required document fields
   */
  protected validateDocument(data: any): boolean {
    if (!data.name && !data.documentName && !data.SPDXID) {
      this.debug("Missing required document fields");
      return false;
    }
    return true;
  }

  /**
   * Validate required package fields
   */
  protected validatePackage(data: any): boolean {
    if (!data.name) {
      this.debug("Package missing required 'name' field");
      return false;
    }
    return true;
  }

  /**
   * Build a standard SPDX document structure
   */
  protected buildSBOMDocument(
    name: string,
    version: string,
    dataLicense: string,
    documentNamespace: string | null | undefined,
    creationInfo: any,
    packages: SBOMPackage[],
  ): SBOMDocument {
    return {
      name,
      version,
      dataLicense,
      documentNamespace: documentNamespace || undefined,
      creationInfo,
      packages,
    };
  }

  /**
   * Handle parsing errors consistently
   */
  protected handleError(error: any, context: string): null {
    this.debug(`Error parsing SPDX ${context}: ${error.message}`);
    return null;
  }

  /**
   * Extract supplier information in a standard format
   */
  protected extractSupplier(supplierField?: string | null): string | undefined {
    if (!supplierField) {
      return undefined;
    }

    // Handle "Organization: Name" or "Person: Name" format
    const match = supplierField.match(/^(?:Organization|Person):\s*(.+)$/);
    return match ? match[1].trim() : supplierField.trim();
  }

  /**
   * Extract version from package info, handling various formats
   */
  protected extractVersion(versionInfo?: string | null): string {
    if (!versionInfo) {
      return "unknown";
    }

    // Clean up version string
    return versionInfo.replace(/^v/, "").trim() || "unknown";
  }

  /**
   * Normalize license information
   */
  protected normalizeLicense(license?: string | null): string | undefined {
    if (!license) {
      return undefined;
    }

    // Handle NOASSERTION and NONE special values
    if (license === "NOASSERTION" || license === "NONE") {
      return undefined;
    }

    return license.trim();
  }
}
