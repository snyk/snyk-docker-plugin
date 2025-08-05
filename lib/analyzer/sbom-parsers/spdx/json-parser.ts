import { SBOMDocument, SBOMPackage } from "../types";
import { BaseSPDXParser, SPDXPackage } from "./base-parser";

/**
 * SPDX JSON format parser
 */
export class SPDXJSONParser extends BaseSPDXParser {
  constructor() {
    super("json");
  }

  public canParse(content: string): boolean {
    try {
      const trimmed = content.trim();
      if (!trimmed.startsWith("{")) {
        return false;
      }

      const parsed = JSON.parse(content);
      return !!(parsed.spdxVersion && parsed.dataLicense);
    } catch {
      return false;
    }
  }

  public parse(content: string): SBOMDocument | null {
    try {
      const doc = JSON.parse(content);

      if (!this.validateDocument(doc)) {
        return null;
      }

      // Extract document metadata
      const documentName =
        doc.name || doc.documentName || "Unknown SPDX Document";
      const spdxVersion = doc.spdxVersion || "SPDX-2.2";
      const dataLicense = doc.dataLicense || "CC0-1.0";
      const documentNamespace = doc.documentNamespace;

      // Extract creation info
      const creationInfo = this.extractCreationInfo(doc);

      // Extract and convert packages
      const packages = this.extractPackages(doc);

      // Process relationships for dependencies
      this.processRelationships(doc, packages);

      return this.buildSBOMDocument(
        documentName,
        spdxVersion,
        dataLicense,
        documentNamespace,
        creationInfo,
        packages,
      );
    } catch (error) {
      return this.handleError(error, "JSON");
    }
  }

  private extractCreationInfo(doc: any) {
    const creationInfo = doc.creationInfo || {};

    const created = creationInfo.created || "";
    const creators = Array.isArray(creationInfo.creators)
      ? creationInfo.creators
      : creationInfo.creators
      ? [creationInfo.creators]
      : [];
    const licenseListVersion = creationInfo.licenseListVersion;

    return this.buildCreationInfo(created, creators, licenseListVersion);
  }

  private extractPackages(doc: any): SBOMPackage[] {
    const packages = doc.packages || [];
    const sbomPackages: SBOMPackage[] = [];

    for (const pkg of packages) {
      if (!this.validatePackage(pkg)) {
        continue;
      }

      const spdxPackage: SPDXPackage = {
        SPDXID: pkg.SPDXID || "",
        name: pkg.name,
        versionInfo: this.extractVersion(pkg.versionInfo),
        downloadLocation: pkg.downloadLocation,
        filesAnalyzed: pkg.filesAnalyzed,
        licenseConcluded: this.normalizeLicense(pkg.licenseConcluded),
        licenseDeclared: this.normalizeLicense(pkg.licenseDeclared),
        copyrightText: pkg.copyrightText,
        supplier: this.extractSupplier(pkg.supplier),
        externalRefs: pkg.externalRefs || [],
        checksums: pkg.checksums || [],
      };

      sbomPackages.push(this.convertToSBOMPackage(spdxPackage));
    }

    return sbomPackages;
  }

  private processRelationships(doc: any, packages: any[]) {
    const relationships = doc.relationships || [];

    // Create a map for quick package lookup by SPDX ID
    const packageMap = new Map();
    packages.forEach((pkg, index) => {
      const spdxId = doc.packages?.[index]?.SPDXID;
      if (spdxId) {
        packageMap.set(spdxId, pkg);
      }
    });

    // Process dependency relationships
    for (const rel of relationships) {
      if (rel.relationshipType === "DEPENDS_ON") {
        const fromPkg = packageMap.get(rel.spdxElementId);
        const toPkg = packageMap.get(rel.relatedSpdxElement);

        if (fromPkg && toPkg) {
          fromPkg.dependencies = fromPkg.dependencies || [];
          fromPkg.dependencies.push(toPkg.name);
        }
      } else if (rel.relationshipType === "DEPENDENCY_OF") {
        const fromPkg = packageMap.get(rel.relatedSpdxElement);
        const toPkg = packageMap.get(rel.spdxElementId);

        if (fromPkg && toPkg) {
          fromPkg.dependencies = fromPkg.dependencies || [];
          fromPkg.dependencies.push(toPkg.name);
        }
      }
    }
  }
}
